// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

public struct DaemonServiceEvent: Sendable {
    public let event: Event
    public let profileID: UUID?
    public let ownerUID: UInt32?
    public init(event: Event, profileID: UUID?, ownerUID: UInt32?) {
        self.event = event; self.profileID = profileID; self.ownerUID = ownerUID
    }
}

/// Shared executable/host wiring; owns and cancels the ordered event forwarding task.
public final class DaemonComposition: Sendable {
    public let controller: TunnelController
    public let dispatcher: DaemonDispatcher
    private let fence: StartupFence
    private let allocate: @Sendable () throws -> UInt64
    private let reportingClock: XPCClock
    private let reporting: Task<Void, Never>
    private let forwarding: Task<Void, Never>

    /// A startup input refresh past this bound no longer holds the restore or the first publication (M03-T01 review).
    public static let startupRefreshBound: Duration = .seconds(5)

    public init(
        controller: TunnelController, daemonVersion: String, daemonBuild: Int,
        minimumClientBuild: Int, minimumDaemonBuild: Int = 0,
        authorisation: DaemonAuthorisation = DaemonAuthorisation(),
        nextStatusSequence: (@Sendable () throws -> UInt64)? = nil,
        statusJournal: StatusPublicationJournal = StatusPublicationJournal(),
        reportingClock: XPCClock = .continuous,
        handoffLog: (@Sendable (String) -> Void)? = nil,
    ) {
        self.controller = controller
        let allocate: @Sendable () throws -> UInt64 = nextStatusSequence ?? { try statusJournal.next() }
        let fence = StartupFence()
        self.fence = fence
        self.reportingClock = reportingClock
        self.allocate = allocate
        let unnumbered: @Sendable () throws -> UInt64 = { 0 }
        let dispatcher = DaemonDispatcher(
            service: controller, daemonVersion: daemonVersion, daemonBuild: daemonBuild,
            minimumClientBuild: max(minimumClientBuild, ProtocolCompatibility.minimumClientBuild),
            minimumDaemonBuild: max(minimumDaemonBuild, ProtocolCompatibility.minimumDaemonBuild), authorisation: authorisation,
            clock: reportingClock,
            measureStatus: { try await controller.publicationMeasurement(nextSequence: allocate) },
            secretFailure: { failure in
                DaemonDiagnostics.secretsHandoffFailure(failure, emit: handoffLog)
            },
        )
        self.dispatcher = dispatcher
        reporting = Task { await dispatcher.startHeartbeat() }
        forwarding = Task {
            for await received in controller.serviceEvents {
                guard !Task.isCancelled else { break }
                let item: DaemonServiceEvent
                var delivered = true
                if case .status = received.event {
                    // Before the run's first publication (DEC-011), or with no subscriber, the status is measured for the
                    // diagnostics only: unnumbered and undelivered, so it cannot take a sequence number.
                    delivered = fence.isOpen ? await dispatcher.hasSubscribers : false
                    let sequence = delivered ? allocate : unnumbered
                    guard let measurement = try? await controller.publicationMeasurement(nextSequence: sequence) else { continue }
                    item = DaemonServiceEvent(
                        event: .status(measurement.status),
                        profileID: measurement.status.activeProfileID ?? received.profileID,
                        ownerUID: measurement.ownerUID,
                    )
                } else {
                    item = received
                }
                if let line = await controller.recordDiagnostics(item) {
                    await dispatcher.publish(.log(line), profileID: item.profileID, ownerUID: item.ownerUID)
                }
                if delivered {
                    await dispatcher.publish(item.event, profileID: item.profileID, ownerUID: item.ownerUID)
                }
            }
        }
    }

    /// Runs the production startup wiring with injected listener and monitor steps.
    public func run(
        runtime: DaemonRuntime, startListener: @escaping @Sendable () async -> Void,
        startMonitors: @escaping @Sendable () async throws -> Void,
        refreshUnderlay: @escaping @Sendable () async throws -> Void = {},
        refreshBound: Duration = DaemonComposition.startupRefreshBound,
    ) async {
        // From here, nothing is published or admitted before the restored policy's first publication (DEC-011).
        await dispatcher.armStartupFence(fence)
        let clock = reportingClock
        // Measures the run's first publication (sequence 1) once, publishes it and opens the fence.
        let publishFirst: @Sendable () async -> Void = { [fence, controller, dispatcher, allocate] in
            guard fence.beginCapture() else { return }
            let first = try? await controller.publicationMeasurement(nextSequence: allocate)
            await dispatcher.openStartupFence(first: first)
        }
        await controller.setStartupRetry { [weak runtime] in await runtime?.retryNow() }
        await controller.setStartupResume { [weak runtime] in await runtime?.resumeStartup() }
        await controller.setOnDemandReporters { [weak dispatcher] in await dispatcher?.eligibleWiFiReporterCount() ?? 0 }
        await runtime.run(ports: .init(
            startListener: startListener,
            setRecovering: { [controller, dispatcher] value in
                if value {
                    await controller.markStartupRecovering()
                } else {
                    // Recovery ended, including a start that had nothing to restore.
                    await publishFirst()
                }
                await dispatcher.setRecovering(value)
            },
            reconcile: { [controller] in try await controller.reconcileAtStartup() },
            startMonitors: startMonitors,
            block: { _ in },
            shouldRetry: { [controller] in await controller.shouldRetryStartup() },
            shutdown: { [controller, fence] in
                // Held requests are released into the shutdown rather than left to their deadlines.
                defer { fence.open(first: nil) }
                try await controller.shutdownCleanly()
            },
            prepareBlocking: { [controller] in
                try await Self.refresh(refreshUnderlay, within: refreshBound, clock: clock) {
                    controller.operationLog("startup underlay refresh exceeded its bound; restoring protection without it")
                }
                // The restore has been attempted, whatever its outcome: the journal holds the policy it left, and that is
                // the first publication, captured before this step returns and so before reconciliation or any held request.
                do { try await controller.prepareStartupBlocking() } catch {
                    await publishFirst()
                    throw error
                }
                await publishFirst()
            },
            revision: { [controller] in await controller.startupControlRevision() },
            failure: { [controller] reason, revision in
                do { try await controller.recoveryFailed(reason, expectedControlID: revision) } catch {
                    await publishFirst()
                    throw error
                }
                await publishFirst()
            },
            heartbeat: { [controller] in try await controller.verifyRecoveryProtection() },
            recoveryIncomplete: { [controller] in await controller.needsRecovery },
            log: { [controller] line in controller.operationLog(line) },
        ))
    }

    /// Runs `work` for at most `bound` on `clock`. Past it, the caller proceeds and `expired` runs; the work is cancelled but
    /// may still finish later, as an underlay event would. An error the work throws in time is rethrown.
    package static func refresh(
        _ work: @escaping @Sendable () async throws -> Void, within bound: Duration, clock: XPCClock,
        expired: @escaping @Sendable () -> Void,
    ) async throws {
        let deadline = Mutex<Task<Void, Never>?>(nil)
        let finished: Bool = try await withCheckedThrowingContinuation { continuation in
            let waiter = Mutex<CheckedContinuation<Bool, any Error>?>(continuation)
            let task = Task {
                let result: Result<Bool, any Error>
                do { try await work(); result = .success(true) } catch { result = .failure(error) }
                waiter.withLock { $0.take() }?.resume(with: result)
            }
            deadline.withLock {
                $0 = Task {
                    do { try await clock.sleep(bound) } catch { return }
                    guard let pending = waiter.withLock({ $0.take() }) else { return }
                    task.cancel()
                    pending.resume(returning: false)
                }
            }
        }
        deadline.withLock { $0 }?.cancel()
        if !finished {
            expired()
        }
    }

    deinit { forwarding.cancel(); reporting.cancel(); fence.open(first: nil) }
}

/// Per-run status publication counter (DEC-011): the first publication of a daemon run is 1 and each later one is one
/// higher. Nothing is persisted: a client tells a new run from the daemon instance identity of its hello, not from a number
/// that keeps rising across runs, and the lab drivers read 1 as the first publication after a restart.
public final class StatusPublicationJournal: Sendable {
    private let last = Mutex<UInt64>(0)

    /// Inert production construction.
    public init() {}

    /// Kept for the call sites that pass a state directory; the counter no longer uses one.
    public init(directory _: StateDirectory) {}

    /// Allocates the next sequence of this run.
    public func next() throws -> UInt64 {
        try last.withLock { last in
            guard last < UInt64.max else { throw DaemonFailure.journalExhausted }
            last += 1
            return last
        }
    }
}
