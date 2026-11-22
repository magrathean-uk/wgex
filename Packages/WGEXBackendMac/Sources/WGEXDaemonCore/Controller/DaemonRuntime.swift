// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Listener-first startup with in-process bounded retries. Owns no system adapter or process exit.
public actor DaemonRuntime {
    /// Injected startup and shutdown steps, allowing host tests without privileged operations.
    public struct Ports: Sendable {
        package let revision: @Sendable () async -> UUID?
        package let failure: (@Sendable (RecoveryFailureReason, UUID?) async throws -> Void)?
        package let heartbeat: (@Sendable () async throws -> Void)?
        package let prepareBlocking: @Sendable () async throws -> Void
        package let startListener: @Sendable () async -> Void
        package let setRecovering: @Sendable (Bool) async -> Void
        package let reconcile: @Sendable () async throws -> Void
        package let startMonitors: @Sendable () async throws -> Void
        package let block: @Sendable (RecoveryFailureReason) async -> Void
        package let shouldRetry: @Sendable () async -> Bool
        /// Whether the controller still needs recovery once `reconcile` has returned (M1-30). Absent means it never does.
        package let recoveryIncomplete: (@Sendable () async -> Bool)?
        /// Operation log sink for the runtime's fixed-vocabulary lines (M1-31); absent means the runtime logs nothing.
        package let log: (@Sendable (String) -> Void)?
        package let shutdown: @Sendable () async throws -> Void
        /// Supplies explicit side effects; no default port touches the host.
        public init(
            startListener: @escaping @Sendable () async -> Void,
            setRecovering: @escaping @Sendable (Bool) async -> Void,
            reconcile: @escaping @Sendable () async throws -> Void,
            startMonitors: @escaping @Sendable () async throws -> Void,
            block: @escaping @Sendable (RecoveryFailureReason) async -> Void,
            shouldRetry: @escaping @Sendable () async -> Bool,
            shutdown: @escaping @Sendable () async throws -> Void,
            prepareBlocking: @escaping @Sendable () async throws -> Void = {},
            revision: @escaping @Sendable () async -> UUID? = { nil },
            failure: (@Sendable (RecoveryFailureReason, UUID?) async throws -> Void)? = nil,
            heartbeat: (@Sendable () async throws -> Void)? = nil,
            recoveryIncomplete: (@Sendable () async -> Bool)? = nil,
            log: (@Sendable (String) -> Void)? = nil,
        ) {
            self.revision = revision; self.failure = failure; self.heartbeat = heartbeat
            self.recoveryIncomplete = recoveryIncomplete; self.log = log
            self.prepareBlocking = prepareBlocking
            self.startListener = startListener; self.setRecovering = setRecovering; self.reconcile = reconcile
            self.startMonitors = startMonitors; self.block = block; self.shouldRetry = shouldRetry; self.shutdown = shutdown
        }
    }

    package let clock: any DaemonClock
    private var ports: Ports?
    private var retry: Task<Void, Never>?
    private var running = false
    private var queued = false
    private var listenerReady = false
    private var heartbeat: Task<Void, Never>?
    package private(set) var attempt = 0
    private var stopped = false
    /// Whether startup has completed successfully.
    public private(set) var isRecovering = true
    /// Injects a monotonic clock for deterministic retry tests.
    public init(clock: any DaemonClock = ContinuousDaemonClock()) {
        self.clock = clock
    }

    deinit { retry?.cancel(); heartbeat?.cancel() }

    /// Starts the listener before any reconciliation or monitor step; failures remain in this process.
    public func run(ports: Ports) async {
        guard self.ports == nil else { return }
        self.ports = ports
        guard !stopped, !Task.isCancelled else { return }
        await ports.setRecovering(true)
        guard !stopped, !Task.isCancelled else { return }
        await ports.startListener()
        guard !stopped, !Task.isCancelled else { return }
        listenerReady = true
        if let check = ports.heartbeat {
            heartbeat = Task { [clock] in
                while !Task.isCancelled {
                    do { try await clock.sleep(for: .seconds(5)); try Task.checkCancellation() }
                    catch { return }
                    do { try await check() } catch { /* The controller publishes measurement failure and retries next tick. */ }
                }
            }
        }
        await recover()
    }

    /// Retries immediately on an underlay notification, serialised with a pending attempt.
    public func retryNow() async {
        guard !stopped, isRecovering else { return }
        if running || !listenerReady {
            queued = true; return
        }
        retry?.cancel(); retry = nil
        await recover()
    }

    private func recover() async {
        guard let ports, !running, !stopped, isRecovering else { return }
        running = true
        defer { running = false }
        repeat {
            queued = false
            let revision = await ports.revision()
            guard !stopped, !Task.isCancelled else { return }
            do {
                let shouldRetry = await ports.shouldRetry()
                guard !stopped, !Task.isCancelled else { return }
                // Nothing to restore, or an inert launch behind the uninstall fence: the fresh install that lifts the fence
                // re-enters this sequence through `resumeStartup` (M05-T18).
                guard shouldRetry else { await recovered(ports); continue }
                try await ports.prepareBlocking()
                guard !stopped, !Task.isCancelled else { return }
                do { try await ports.startMonitors() }
                catch { throw DaemonFailure.startup(.monitorStartFailed) }
                guard !stopped, !Task.isCancelled else { return }
                try await ports.reconcile()
                guard !stopped, await ports.revision() == revision else { throw CancellationError() }
                try await requireRecoveryComplete(ports)
                await recovered(ports)
            } catch { await recordFailure(error, revision: revision, ports: ports) }
        } while queued && isRecovering && !stopped
    }

    /// Re-enters the startup sequence `run` began (underlay refresh, startup protection, monitors, reconciliation), as a
    /// normal launch runs it: a launch behind the uninstall fence skipped it, and the fresh install that lifts the fence
    /// calls this so the daemon ends in the state a normal launch leaves (M05-T18). Recovery is armed before this returns;
    /// the attempt runs on its own task, with the startup backoff on failure.
    public func resumeStartup() async {
        guard let ports, listenerReady, !stopped else { return }
        isRecovering = true; attempt = 0
        await ports.setRecovering(true)
        guard !stopped, isRecovering else { return }
        if running {
            queued = true; return
        }
        retry?.cancel()
        retry = Task { [weak self] in await self?.recover() }
    }

    /// A reconcile that returned while the controller still needs recovery has not recovered anything: it takes the failure
    /// path (and its backoff) rather than declare recovery over with nothing left to retry (M1-30 NF1).
    private func requireRecoveryComplete(_ ports: Ports) async throws {
        if let incomplete = ports.recoveryIncomplete, await incomplete() {
            // One line per refusal. The backoff that follows (5, 15, 60 s) bounds the rate only while the failure port
            // succeeds: if it throws, recordFailure requeues at once and the next refusal logs again (M1-31 INFO 1; in
            // production that port throws only when a control rotates the identity or the publication is cancelled, and
            // each extra line then costs a full reconcile). Fixed words, no values.
            ports.log?("recovery guard: reconcile returned with recovery still needed; recovered() refused, backing off")
            throw DaemonFailure.startup(.reconciliationFailed)
        }
    }

    private func recordFailure(_ error: any Error, revision: UUID?, ports: Ports) async {
        guard !stopped else { return }
        if error is StartupOperationExpired {
            // The watchdog has published the measured state and rotated the revision itself: back off 5, 15, 60 s rather
            // than requeue at once. A retry already queued by an underlay event or a user control still runs now.
            if !queued {
                await scheduleRetry()
            }
            return
        }
        let currentRevision = await ports.revision()
        guard !stopped else { return }
        if error is CancellationError || currentRevision != revision {
            queued = true; return
        }
        do {
            let reason = (error as? DaemonFailure)?.recoveryReason ?? .reconciliationFailed
            if let failure = ports.failure {
                try await failure(reason, revision)
            } else {
                await ports.block(reason)
            }
        } catch { queued = true }
        if !queued {
            await scheduleRetry()
        }
    }

    private func recovered(_ ports: Ports) async {
        guard !stopped, !Task.isCancelled else { return }
        attempt = 0; isRecovering = false; queued = false
        retry?.cancel(); retry = nil
        await ports.setRecovering(false)
    }

    private func scheduleRetry() async {
        guard let ports, await ports.shouldRetry(), !stopped, !queued else { return }
        let seconds = [5, 15, 60][min(attempt, 2)]
        attempt += 1
        retry = Task { [weak self, clock] in
            do { try await clock.sleep(for: .seconds(seconds)); try Task.checkCancellation(); await self?.recover() }
            catch { /* Replacement or shutdown cancels only this runtime's retry. */ }
        }
    }

    /// Cancels owned retry work. Does not release any policy token.
    public func stop() {
        stopped = true; retry?.cancel(); retry = nil; heartbeat?.cancel(); heartbeat = nil
    }

    /// SIGTERM uses the same injected orderly-shutdown step as host tests.
    public func shutdown() async throws {
        stop()
        guard let ports else { throw DaemonFailure.startup(.reconciliationFailed) }
        try await ports.shutdown()
    }
}

package extension DaemonRuntime {
    func sleepForTick() async throws {
        try await clock.sleep(for: .seconds(5))
    }

    func waitForShutdownRetry() async {
        try? await clock.sleep(for: .seconds(5))
    }
}

internal extension DaemonRuntime {
    /// Startup is cancelled and drained when termination completes; the loop starts only after startup returns.
    func serveUntilTermination(
        events: AsyncStream<Void>, startup: @escaping @Sendable () async -> Void,
        mainLoop: @escaping @Sendable () async -> Void,
    ) async {
        await withTaskGroup(of: RuntimeWork.self) { group in
            group.addTask { await startup(); return .startup }
            group.addTask {
                for await _ in events {
                    break
                }
                return .termination
            }
            while let work = await group.next() {
                if work == .termination {
                    group.cancelAll()
                    return
                }
                if work == .startup, !stopped, !Task.isCancelled {
                    group.addTask { await mainLoop(); return .loop }
                }
            }
        }
    }
}

private enum RuntimeWork: Sendable { case startup, loop, termination }
