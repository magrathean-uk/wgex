// SPDX-License-Identifier: Apache-2.0 AND MIT

// Adapted from firezone swift/apple FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift at
// 229ac31b37b5fbde2961e7f87df8181abd7fd46f, Apache-2.0
// Copyright Firezone, Inc. Licensed under Apache-2.0; see Vendor/firezone/NOTICE and LICENSE.
import Foundation
import Synchronization
import WGEXCore

/// Broadcasts ordered snapshots; each subscriber receives the current state first.
private final class StatusHub: Sendable {
    private struct State {
        var latest = TunnelStatus.idle
        var subscribers: [UUID: AsyncStream<TunnelStatus>.Continuation] = [:]
    }

    private let state = Mutex(State())
    func stream() -> AsyncStream<TunnelStatus> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<TunnelStatus>.makeStream(bufferingPolicy: .bufferingNewest(64))
        state.withLock { state in
            state.subscribers[id] = continuation
            continuation.yield(state.latest)
        }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { _ = $0.subscribers.removeValue(forKey: id) }
        }
        return stream
    }

    func publish(_ status: TunnelStatus) {
        state.withLock { state in
            state.latest = status
            for subscriber in state.subscribers.values {
                subscriber.yield(status)
            }
        }
    }
}

/// Preferences operations are serialised across suspension points by a FIFO gate. Intent revisions suppress obsolete starts/stops after a
/// newer user request arrives. Status follows the manager that is up: a tunnel started from Settings > VPN, by on-demand or by this client
/// is reported against its own profile id, and a switch moves the report to the manager coming up.
public actor NEManagerClient: TunnelBackend {
    public nonisolated let capabilities: BackendCapabilities = [.onDemand, .allowLAN, .transportSwitching]
    private let system: any VPNManagerSystem
    private let platform: ProfilePlatform
    private let identifiers: BuildIdentifiers
    private let purge: @Sendable (UUID) async throws -> Void
    private let providerMessageTimeout: Duration
    private let restartConfirmationTimeout: Duration
    private let sleep: @Sendable (Duration) async throws -> Void
    private nonisolated let hub = StatusHub()
    private var records: [VPNManagerRecord]?
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var intent: UInt64 = 0
    private var generation = Generation.initial
    /// The manager whose status is reported.
    private var focus: UUID?
    /// Latest status per manager from the system's events.
    private var statuses: [UUID: VPNStatus] = [:]
    /// Profile id per manager, kept across reloads so a status always names its profile.
    private var profileIDs: [UUID: UUID] = [:]
    private var published: (manager: UUID, status: VPNStatus)?
    private var sequences: [UUID: UInt64] = [:]
    private var observer: Task<Void, Never>?
    /// What each running tunnel last took, kept from the moment a changed profile is saved over it until the change is
    /// applied or the tunnel goes down, so a retried install re-applies a change that failed instead of skipping it.
    private var unapplied: [UUID: VPNManagerRecord] = [:]
    /// The manager whose statistics subscription may be active: set once the request is handed to the system, cleared only
    /// once an unsubscribe has followed it, so no subscription the provider took or may still take is ever left untracked.
    private var statisticsSubscription: UUID?
    /// Statistics requests run one at a time, in arrival order, apart from the preferences gate.
    private var statisticsBusy = false
    private var statisticsWaiters: [CheckedContinuation<Void, Never>] = []
    /// Advanced by every start, stop and remove as it arrives. An install belongs to the operation current when it
    /// arrived; a later start, stop or remove supersedes it.
    private var operation: UInt64 = 0
    /// The restart confirmation under way, ended as interrupted the moment a newer operation arrives.
    private var confirmation: (operation: UInt64, gate: SingleResume<Void>)?
    /// A failed save invalidates the entire loaded cache, even if its value appears equivalent.
    public private(set) var failedWrite = false
    package var pendingOperationCount: Int {
        waiters.count
    }

    package var pendingStatisticsOperationCount: Int {
        statisticsWaiters.count
    }

    public init(
        system: any VPNManagerSystem, platform: ProfilePlatform, identifiers: BuildIdentifiers = .current,
        purgeSecrets: @escaping @Sendable (UUID) async throws -> Void = { _ in throw TunnelError.backendUnavailable },
        providerMessageTimeout: Duration = .seconds(10),
        restartConfirmationTimeout: Duration = .seconds(45),
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
    ) {
        self.system = system; self.platform = platform; self.identifiers = identifiers; purge = purgeSecrets
        self.providerMessageTimeout = providerMessageTimeout; self.restartConfirmationTimeout = restartConfirmationTimeout
        self.sleep = sleep
    }

    /// What `install` throws when an edit's restart stopped the tunnel and it did not come back (start refused, or down
    /// again before connecting); the tunnel is then down. The code is outside the engine's own (-1 to -9, -99, wgex.h).
    public static let reconnectFailure = TunnelError.engine(code: -100)

    /// Also loads the managers and starts observing them, so a tunnel that is already up is reported at launch without any other call.
    public nonisolated func statusUpdates() -> AsyncStream<TunnelStatus> {
        let stream = hub.stream()
        Task { [weak self] in await self?.prime() }
        return stream
    }

    /// A connected manager takes a changed profile without a manual reconnect, as the official app does: protection flags that only a new
    /// connection reads restart it; any other change to what the tunnel uses reloads it through the provider, falling back to stop and
    /// start when the reload cannot be delivered. A reload the provider rejects has already ended the tunnel there; its error is thrown
    /// here. Names and on-demand rules apply with the save alone.
    ///
    /// Returning means the edit has finished applying, never merely that it was requested:
    /// - a profile whose tunnel is not running, or a name or on-demand change, once it is saved;
    /// - an in-place reload once the provider answers `.ok`, which it sends only after the running tunnel has taken the new settings;
    /// - a restart (protection flags, or a reload that could not be delivered or read) only once the system reports the edited manager
    ///   connected after this install's own start, which it requests only after the stop is confirmed and only while the manager holds this
    ///   edit's revision (`VPNManagerSystem.startConfirmed`).
    ///
    /// Otherwise it throws: `reconnectFailure` when the restarted tunnel did not come back (it is then down); `.cancelled` when the caller
    /// is cancelled or a start, stop or remove arrives while the restart waits (that newer operation goes ahead at once, and a connection
    /// seen later never completes this install; a newer install waits for this one, so it decides on the tunnel this one left); `.timedOut`
    /// when the stop is not confirmed in time (the old profile may still run; a retry applies the edit again) or no connection is seen
    /// within the restart's bound (`restartConfirmationTimeout`; no timer ever ends it in success); and the save's or the provider's own
    /// error otherwise.
    public func install(_ profile: TunnelProfile) async throws(TunnelError) {
        let arrival = operation
        await acquire()
        defer { release() }
        do {
            guard !profile.validate().contains(where: { $0.severity == .error }) else {
                throw TunnelError.invalidConfiguration(.invalidProfile)
            }
            try await loadIfNeeded()
            let configuration = ProtocolConfigurationBuilder.build(profile, platform: platform, identifiers: identifiers)
            let old = find(profile.id)
            var desired = old ?? VPNManagerRecord(id: profile.id, configuration: configuration, name: profile.name)
            desired.configuration = configuration; desired.name = profile.name; desired.isEnabled = true
            desired.isOnDemandEnabled = old?.isOnDemandEnabled ?? false
            desired.profileRevision = Self.profileRevision(profile)
            try await write(desired)
            if let old, Self.isRunning(statuses[old.id] ?? old.status) {
                // The saved record says what the tunnel should run, not what it runs: a change saved by an install whose
                // apply failed is compared against what the tunnel took last, so the retry applies it again.
                let running = unapplied[old.id] ?? old
                unapplied[old.id] = running
                try await apply(desired, over: running, operation: arrival)
                unapplied[old.id] = nil
            }
        } catch { throw Self.map(error) }
    }

    /// Arms the manager when its saved on-demand rules hold any rule and disarms it otherwise; never starts or stops a tunnel.
    public func followOnDemandRules(_ id: UUID) async throws(TunnelError) {
        await acquire(); defer { release() }
        do {
            try await loadIfNeeded()
            guard var record = find(id) else { throw TunnelError.profileNotFound(id) }
            record.isOnDemandEnabled = !record.configuration.onDemandRules.isEmpty; try await write(record)
        } catch { throw Self.map(error) }
    }

    public func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
        intent &+= 1
        supersede()
        await acquire()
        defer { release() }
        do {
            try await loadIfNeeded()
            guard let record = find(id) else { throw TunnelError.profileNotFound(id) }
            try await system.remove(record.id)
            records = nil; statuses[record.id] = nil; profileIDs[record.id] = nil; unapplied[record.id] = nil
            if focus == record.id {
                focus = nil; published = nil; hub.publish(.idle)
            }
            if purgeSecrets {
                try await purge(id)
            }
        } catch { throw Self.map(error) }
    }

    public func start(_ id: UUID, transport: TransportID?) async throws(TunnelError) {
        intent &+= 1
        supersede()
        let revision = intent
        await acquire()
        defer { release() }
        do {
            guard revision == intent else { throw TunnelError.cancelled }
            try await loadIfNeeded()
            guard var record = find(id) else { throw TunnelError.profileNotFound(id) }
            record.isEnabled = true; record.isOnDemandEnabled = !record.configuration.onDemandRules.isEmpty
            try await write(record)
            guard revision == intent else { throw TunnelError.cancelled }
            generation = generation.next(); focus = record.id
            publish(.connecting, for: record.id)
            try await system.start(record.id, transport: transport?.rawValue)
        } catch { throw Self.map(error) }
    }

    public func stop(_ id: UUID) async throws(TunnelError) {
        intent &+= 1
        supersede()
        let revision = intent
        await acquire()
        defer { release() }
        do {
            try await loadIfNeeded()
            guard var record = find(id) else { throw TunnelError.profileNotFound(id) }
            guard revision == intent else { throw TunnelError.cancelled }
            record.isOnDemandEnabled = false
            try await write(record)
            guard revision == intent else { throw TunnelError.cancelled }
            // Stopping a profile that is not up never takes the report from the tunnel that is.
            if focus == nil || focus == record.id || VPNManagerRecord.isLive(statuses[record.id] ?? record.status) {
                focus = record.id; publish(.disconnecting, for: record.id)
            }
            try await system.stop(record.id)
        } catch { throw Self.map(error) }
    }

    /// One sample of the reported tunnel: per-peer bytes received and sent and the last handshake.
    public func statistics() async throws(TunnelError) -> TunnelStatistics {
        do {
            guard let focus else { throw TunnelError.backendUnavailable }
            switch try await awaitReply(send(focus, .statistics)) {
            case let .statistics(sample): return sample
            case let .error(error): throw error
            default: throw TunnelError.backendUnavailable
            }
        } catch { throw Self.map(error) }
    }

    /// Starts the provider's statistics subscription on the reported tunnel. The caller samples with `statistics()` only while it shows
    /// them and ends with `stopStatistics()`; nothing is polled here. A request whose outcome is unknown (no reply by the deadline,
    /// cancelled after it was handed over, unreadable reply) is withdrawn: this throws at once, and the unsubscribe follows the request's
    /// send in the background, so a request that reaches the provider late is still ended after it.
    public func startStatistics(interval: TimeInterval) async throws(TunnelError) {
        await acquireStatistics()
        // A withdrawal takes the gate with it and releases it once its unsubscribe has followed the request.
        var withdrawing = false
        defer {
            if !withdrawing {
                releaseStatistics()
            }
        }
        do {
            try Task.checkCancellation()
            guard let focus else { throw TunnelError.backendUnavailable }
            if let previous = statisticsSubscription, previous != focus {
                await unsubscribe(previous)
            }
            let kept = statisticsSubscription
            let exchange = try send(focus, .subscribeStats(interval: interval))
            statisticsSubscription = focus
            let reply: ProviderReply
            do {
                reply = try await awaitReply(exchange)
            } catch {
                withdrawing = true
                withdraw(focus, after: exchange.delivery)
                throw error
            }
            switch reply {
            case .ok: return
            case let .error(error):
                // The provider rejected the request and kept whatever subscription it had; a stop still ends that one.
                statisticsSubscription = kept
                throw error
            default:
                await unsubscribe(focus)
                throw TunnelError.backendUnavailable
            }
        } catch { throw Self.map(error) }
    }

    /// Ends the subscription `startStatistics` began, after any start or withdrawal still under way. A tunnel that has gone
    /// away has no subscription left, so an undelivered message is not an error.
    public func stopStatistics() async {
        await acquireStatistics()
        defer { releaseStatistics() }
        guard let manager = statisticsSubscription else { return }
        await unsubscribe(manager)
    }

    /// Explicit shutdown releases the status observation without a retained actor/task cycle.
    public func shutdown() {
        observer?.cancel(); observer = nil
    }
}

/// A provider message handed to the system. `gate` takes the first outcome for the caller; `delivery` is the system's send
/// itself and ends only when that send has returned or thrown, which can be after the deadline or the caller's cancellation.
private struct ProviderExchange: Sendable {
    let gate: SingleResume<Data>
    let delivery: Task<Void, Never>
}

private extension NEManagerClient {
    /// Hands the message to the system at once, unless the caller has already been cancelled.
    func send(_ id: UUID, _ message: ProviderMessage) throws -> ProviderExchange {
        try Task.checkCancellation()
        let data = try ProviderCodec.encode(message)
        let gate = SingleResume<Data>(), system = system
        let delivery = Task.detached {
            do {
                try await gate.finish(.success(system.sendProviderMessage(id, data: data)))
            } catch { gate.finish(.failure(error)) }
        }
        gate.attach(delivery)
        return ProviderExchange(gate: gate, delivery: delivery)
    }

    /// A reply that misses the deadline fails with `.timedOut`; the abandoned send is cancelled and its late result dropped.
    /// The race is unstructured on purpose: a system that ignores cancellation must not hold the caller past the deadline.
    func awaitReply(_ exchange: ProviderExchange) async throws -> ProviderReply {
        let gate = exchange.gate, sleep = sleep, timeout = providerMessageTimeout
        let data = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                gate.install(continuation)
                gate.attach(Task.detached {
                    do {
                        try await sleep(timeout)
                        gate.finish(.failure(TunnelError.timedOut))
                    } catch {}
                })
            }
        } onCancel: { gate.finish(.failure(CancellationError())) }
        return try ProviderCodec.decode(ProviderReply.self, from: data)
    }

    /// Ends a subscription whose request may still reach the provider, without holding the caller. The subscription stays
    /// tracked and the statistics gate held until the request's send has ended and an unsubscribe has followed it, so no
    /// stop or start overtakes the request and a late delivery is always ended after it arrives.
    func withdraw(_ manager: UUID, after delivery: Task<Void, Never>) {
        Task { await self.finishWithdrawal(manager, after: delivery) }
    }

    func finishWithdrawal(_ manager: UUID, after delivery: Task<Void, Never>) async {
        defer { releaseStatistics() }
        await delivery.value
        await unsubscribe(manager)
    }

    /// Best effort, and sent even when the caller has been cancelled, so a withdrawn subscription is always asked to end.
    /// Returns once the system's send of it has ended, so no later statistics request reaches the provider ahead of it.
    func unsubscribe(_ manager: UUID) async {
        await Task { await self.sendUnsubscribe(manager) }.value
        if statisticsSubscription == manager {
            statisticsSubscription = nil
        }
    }

    func sendUnsubscribe(_ manager: UUID) async {
        guard let exchange = try? send(manager, .unsubscribeStats) else { return }
        _ = try? await awaitReply(exchange)
        await exchange.delivery.value
    }

    static func isRunning(_ status: VPNStatus) -> Bool {
        status == .connected || status == .reasserting
    }

    static func isCancellation(_ error: any Error) -> Bool {
        error is CancellationError || (error as? TunnelError) == .cancelled
    }

    func apply(_ desired: VPNManagerRecord, over old: VPNManagerRecord, operation: UInt64) async throws {
        if old.configuration.ios != desired.configuration.ios || old.configuration.enforceRoutes != desired.configuration.enforceRoutes {
            try await restart(desired, operation: operation)
        } else if old.profileRevision != desired.profileRevision {
            try await reloadTunnel(desired, operation: operation)
        }
    }

    /// The provider reloads in place and, if that fails, ends the tunnel itself; a reload it never received or answered
    /// in an unknown form is replaced by stop and start, so the tunnel never runs half of each profile.
    func reloadTunnel(_ record: VPNManagerRecord, operation: UInt64) async throws {
        let reply: ProviderReply
        do {
            reply = try await awaitReply(send(record.id, .reload(profileID: record.configuration.profileID)))
        } catch {
            guard !Self.isCancellation(error) else { throw error }
            try await restart(record, operation: operation)
            return
        }
        switch reply {
        case .ok: return
        case let .error(failure): throw failure
        default: try await restart(record, operation: operation)
        }
    }

    /// Stop, confirmed down by the system, then a start that counts only once the edited manager is seen connected.
    func restart(_ record: VPNManagerRecord, operation: UInt64) async throws {
        try await system.stop(record.id)
        // Down now: whatever runs next reads the saved profile, whether or not this start completes.
        unapplied[record.id] = nil
        try await confirmStart(record, operation: operation)
    }

    /// Ends any restart confirmation still waiting, as interrupted, and opens a new operation.
    func supersede() {
        operation &+= 1
        confirmation?.gate.finish(.failure(TunnelError.cancelled))
        confirmation = nil
    }

    /// The first outcome wins: the system's confirmation (connected or failed), the bound (`.timedOut`, never success) or
    /// interruption (caller cancelled, newer operation). Losers are cancelled; the lossy status stream is never read.
    func confirmStart(_ record: VPNManagerRecord, operation: UInt64) async throws {
        guard operation == self.operation else { throw TunnelError.cancelled }
        let gate = SingleResume<Void>(), system = system, sleep = sleep, bound = restartConfirmationTimeout
        let id = record.id, revision = record.profileRevision
        confirmation = (operation, gate)
        defer {
            if confirmation?.gate === gate {
                confirmation = nil
            }
        }
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    gate.install(continuation)
                    gate.attach(Task.detached {
                        do {
                            try await system.startConfirmed(id, revision: revision)
                            gate.finish(.success(()))
                        } catch { gate.finish(.failure(error)) }
                    })
                    gate.attach(Task.detached {
                        do {
                            try await sleep(bound)
                            gate.finish(.failure(TunnelError.timedOut))
                        } catch {}
                    })
                }
            } onCancel: { gate.finish(.failure(CancellationError())) }
        } catch {
            if Self.isCancellation(error) || (error as? TunnelError) == .timedOut {
                throw error
            }
            throw Self.reconnectFailure
        }
    }

    func prime() async {
        guard records == nil || observer == nil else { return }
        await acquire()
        defer { release() }
        try? await loadIfNeeded()
    }

    func publish(_ status: VPNStatus, for manager: UUID) {
        var snapshot = Self.status(status, generation: generation)
        // An idle snapshot names no tunnel, as the daemon's does.
        snapshot.activeProfileID = status == .disconnected ? nil : profileIDs[manager] ?? manager
        published = (manager, status)
        hub.publish(snapshot)
    }

    /// A manager coming up takes the report whoever started it; one going down is reported only while it holds the report,
    /// and hands it to another manager that is already up. The adapter repeats every manager's status on each change, so
    /// a repeated status is no change: a manager still listed as connected while another comes up keeps no claim.
    func receive(_ event: VPNStatusEvent) {
        let id = event.managerID
        // Only managers this client loaded count: another VPN's tunnel never takes the report or the statistics.
        guard profileIDs[id] != nil, event.sequence > sequences[id, default: 0] else { return }
        sequences[id] = event.sequence
        guard statuses[id] != event.status else { return }
        statuses[id] = event.status
        if let index = records?.firstIndex(where: { $0.id == id }) {
            records?[index].status = event.status
        }
        // A tunnel that has gone down reads the saved profile when it next connects.
        if event.status == .disconnected || event.status == .invalid {
            unapplied[id] = nil
        }
        if VPNManagerRecord.isLive(event.status) {
            let continuing = published.map { $0.manager == id && VPNManagerRecord.isLive($0.status) } ?? false
            if !continuing {
                generation = generation.next()
            }
            focus = id
            publish(event.status, for: id)
        } else if focus == id {
            let next = statuses.filter { $0.key != id && VPNManagerRecord.isLive($0.value) }.min { $0.key.uuidString < $1.key.uuidString }
            if event.status != .disconnecting, let next {
                generation = generation.next(); focus = next.key
                publish(next.value, for: next.key)
            } else {
                publish(event.status, for: id)
            }
        }
    }

    /// The manager reported at launch is the one furthest up, never simply the first listed.
    static func preferred(_ records: [VPNManagerRecord]) -> VPNManagerRecord? {
        let rank: [VPNStatus: Int] = [.connected: 0, .reasserting: 1, .connecting: 2, .disconnecting: 3]
        return records.compactMap { record in rank[record.status].map { (rank: $0, record: record) } }
            .min { ($0.rank, $0.record.id.uuidString) < ($1.rank, $1.record.id.uuidString) }?.record
    }

    func loadIfNeeded() async throws {
        if records == nil {
            try await reload()
        }
        if focus == nil, let record = Self.preferred(records ?? []) {
            focus = record.id
            publish(record.status, for: record.id)
        }
        if observer == nil {
            let stream = await system.statusEvents()
            observer = Task { [weak self] in
                for await event in stream {
                    guard !Task.isCancelled else { break }
                    await self?.receive(event)
                }
            }
        }
    }

    func reload() async throws {
        records = nil
        let loaded = try await system.loadAll().filter { $0.configuration.providerBundleIdentifier == identifiers.tunnelExtension }
        records = loaded
        for record in loaded {
            profileIDs[record.id] = record.configuration.profileID
        }
    }

    func find(_ id: UUID) -> VPNManagerRecord? {
        records?.first { $0.configuration.profileID == id }
    }

    func write(_ desired: VPNManagerRecord) async throws {
        if !failedWrite, records?.contains(desired) == true {
            return
        }
        for attempt in 0 ... 1 {
            do {
                try await system.save(desired)
                try await reload()
                failedWrite = false
                return
            } catch {
                failedWrite = true; records = nil
                guard attempt == 0 else { throw error }
                // Never reuse a manager mutated by the failed save. The adapter replaces its objects on load.
                try await reload()
            }
        }
    }

    func acquire() async {
        if busy {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            busy = true
        }
    }

    func release() {
        if waiters.isEmpty {
            busy = false
        } else {
            waiters.removeFirst().resume()
        }
    }

    func acquireStatistics() async {
        if statisticsBusy {
            await withCheckedContinuation { statisticsWaiters.append($0) }
        } else {
            statisticsBusy = true
        }
    }

    func releaseStatistics() {
        if statisticsWaiters.isEmpty {
            statisticsBusy = false
        } else {
            statisticsWaiters.removeFirst().resume()
        }
    }

    static func map(_ error: any Error) -> TunnelError {
        (error as? TunnelError) ?? (error is CancellationError ? .cancelled : .backendUnavailable)
    }
}

/// Both names use the same serialised implementation; existing NEManagerClient callers remain valid.
public typealias NETunnelBackend = NEManagerClient
