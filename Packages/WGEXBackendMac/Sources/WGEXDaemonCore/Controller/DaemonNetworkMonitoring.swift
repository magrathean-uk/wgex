// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol
import WGEXPolicy

/// A trailing edge shared by every network trigger, bounded under continuous activity.
public struct NetworkEventDebounce: Sendable {
    public private(set) var deadline: Duration?
    private var first: Duration?
    /// Creates an empty debounce window.
    public init() {}
    /// Extends the trailing edge without moving the maximum wait.
    public mutating func receive(at now: Duration) {
        if first == nil {
            first = now
        }
        deadline = min(now + .milliseconds(500), (first ?? now) + .seconds(3))
    }

    /// Consumes the window once its deadline is reached.
    public mutating func take(at now: Duration) -> Bool {
        guard let deadline, now >= deadline else { return false }
        self.deadline = nil; first = nil; return true
    }
}

private enum NetworkTrigger: Sendable {
    case route(RouteNotification), underlay(UnderlayEvent), lifecycle(MonitorAction), action(MonitorAction.Attempt), barrier(UUID), failed
}

/// Merges monitor callbacks into one ordered stream and retries failed batches from the daemon tick.
public actor DaemonNetworkMonitoring {
    private let controller: TunnelController
    private let routes: any RouteMonitoring
    private let underlay: any UnderlayMonitoring
    private let power: any PowerMonitoring
    private let login: any LoginSessionMonitoring
    private let readUnderlay: @Sendable () async throws -> UnderlayEvent
    private let clock: any DaemonClock
    private let recoveryUnderlay: @Sendable (UnderlayEvent) async -> Bool
    private let failure: @Sendable () -> Void
    private var tasks: [Task<Void, Never>] = []
    private var debounceTask: Task<Void, Never>?
    private var debounce = NetworkEventDebounce()
    private var routeModel: RouteMonitorModel
    private var underlayModel = UnderlayMonitorModel()
    private var pending: [NetworkTrigger] = []
    package private(set) var actionRevision: UInt64 = 0
    package var pendingLifecycleRetries: Int {
        queuedActions.count
    }

    private let revisions = MonitorActionRevisions()
    private var streamSink: AsyncStream<NetworkTrigger>.Continuation?
    private var lifecycleBarriers: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var queuedActions: [MonitorAction.Attempt] = []
    private var retryingActions = false
    private var retryAt: Duration?
    private var retryAttempt = 0
    private var needsRestart = false
    private var running = false
    private var reconciling = false
    package var reconciliationInFlight: Bool {
        reconciling
    }

    /// Injects inert adapters and the shared clock; no system work occurs until start.
    public init(
        controller: TunnelController, routes: any RouteMonitoring, underlay: any UnderlayMonitoring,
        power: any PowerMonitoring, login: any LoginSessionMonitoring, ownPID: Int32,
        clock: any DaemonClock = ContinuousDaemonClock(),
        readUnderlay: @escaping @Sendable () async throws -> UnderlayEvent,
        failure: @escaping @Sendable () -> Void = {},
        recoveryUnderlay: @escaping @Sendable (UnderlayEvent) async -> Bool = { _ in false },
    ) {
        self.controller = controller; self.routes = routes; self.underlay = underlay; self.power = power; self.login = login
        self.recoveryUnderlay = recoveryUnderlay
        self.clock = clock; self.readUnderlay = readUnderlay; self.failure = failure; routeModel = RouteMonitorModel(ownPID: ownPID)
    }

    deinit { for task in tasks {
        task.cancel()
    }; debounceTask?.cancel() }

    /// Starts the four producers and one ordered consumer.
    public func start() async throws {
        guard tasks.isEmpty else { return }
        running = true
        do {
            let routeEvents = try await routes.start(), underlayEvents = try await underlay.start()
            let powerEvents = try await power.start(), loginEvents = try await login.start()
            let merged = AsyncStream<NetworkTrigger>.makeStream()
            streamSink = merged.continuation
            tasks = [
                observe(routeEvents, sink: merged.continuation, transform: NetworkTrigger.route),
                observe(underlayEvents, sink: merged.continuation, transform: NetworkTrigger.underlay),
                observe(powerEvents, sink: merged.continuation, transform: { .lifecycle(.power($0)) }),
                observe(loginEvents, sink: merged.continuation, transform: { .lifecycle(.login($0)) }),
                Task { [weak self] in for await event in merged.stream {
                    await self?.enqueue(event)
                } },
            ]
        } catch { await stopAdapters(); running = false; throw error }
    }

    /// Stops only owned notification resources.
    public func stop() async {
        running = false; debounceTask?.cancel(); debounceTask = nil
        await stopAdapters(); pending = []; queuedActions = []; revisions.clear(); retryAt = nil
    }

    private func stopAdapters() async {
        streamSink?.finish(); streamSink = nil
        for continuation in lifecycleBarriers.values {
            continuation.resume()
        }
        lifecycleBarriers = [:]
        for task in tasks {
            task.cancel()
        }; tasks = []
        await routes.stop(); await underlay.stop(); await power.stop(); await login.stop()
    }

    /// Re-reads after errors and restarts terminated monitors with bounded retry frequency.
    public func retryPending() async {
        await retryActions()
        guard running, !reconciling, let retryAt, clock.now >= retryAt else { return }
        if needsRestart {
            await stopAdapters()
            do { try await start(); needsRestart = false }
            catch { running = true; await failed(); return }
        }
        await reconcile()
    }

    private func enqueue(_ event: NetworkTrigger) async {
        guard running else { return }
        if await consumeLifecycle(event) {
            return
        }
        switch event {
        case let .route(notification):
            guard await enqueueRoute(notification) else { return }
        case let .underlay(value):
            guard await enqueueUnderlay(value) else { return }
        case .failed:
            needsRestart = true; await failed(); return
        default: return
        }
        debounce.receive(at: clock.now)
        guard debounceTask == nil, retryAt == nil else { return }
        debounceTask = Task { [weak self] in await self?.waitForBatch() }
    }

    private func enqueueRoute(_ notification: RouteNotification) async -> Bool {
        let identity = await controller.resource(controller.currentGeneration).identity
        routeModel.ignoredIndices = Set([identity?.interfaceIndex].compactMap { $0.flatMap(UInt16.init(exactly:)) })
        guard routeModel.receive(notification, at: clock.now) else { return false }
        if !pending.contains(where: \.isRoute) {
            pending.append(.route(notification))
        }
        return true
    }

    private func enqueueUnderlay(_ value: UnderlayEvent) async -> Bool {
        let previous = underlayModel.current
        if value.readFailed {
            await controller.monitoringFailed()
        }
        guard underlayModel.receive(value) else { return false }
        pending.removeAll(where: \.isUnderlay); pending.append(.underlay(value))
        if await controller.restoresUnderlay(value, previous: previous) {
            retryAt = nil; retryAttempt = 0
        }
        return true
    }

    private func receive(_ event: NetworkTrigger, sink: AsyncStream<NetworkTrigger>.Continuation) {
        guard running else { return }
        if case let .lifecycle(action) = event {
            actionRevision &+= 1
            revisions.receive(action.kind, revision: actionRevision)
            queuedActions.removeAll { $0.action.kind == action.kind }
            sink.yield(.action(.init(action: action, revision: actionRevision, due: clock.now)))
        } else {
            sink.yield(event)
        }
    }

    private func queueRetry(_ attempt: MonitorAction.Attempt) {
        guard running, revisions.matches(attempt.action.kind, revision: attempt.revision) else { return }
        queuedActions.append(.init(action: attempt.action, revision: attempt.revision, due: clock.now + .seconds(5)))
    }

    private func retryActions() async {
        guard running, !retryingActions, let streamSink else { return }
        let now = clock.now
        let due = queuedActions.filter { $0.due <= now }
        guard !due.isEmpty else { return }
        queuedActions.removeAll { $0.due <= now }
        retryingActions = true; defer { retryingActions = false }
        await withCheckedContinuation { continuation in
            let id = UUID(); lifecycleBarriers[id] = continuation
            for attempt in due {
                streamSink.yield(.action(attempt))
            }
            streamSink.yield(.barrier(id))
        }
    }

    private func apply(_ attempt: MonitorAction.Attempt) async {
        let revisions = revisions, action = attempt.action, revision = attempt.revision
        let isCurrent: @Sendable () -> Bool = { revisions.matches(action.kind, revision: revision) }
        guard running, isCurrent() else { return }
        do {
            switch action {
            case let .power(value): try await controller.powerChanged(value, isCurrent: isCurrent)
            case let .login(uid): try await controller.consoleUserChanged(uid, isCurrent: isCurrent)
            }
        } catch { queueRetry(attempt) }
    }

    private func waitForBatch() async {
        while running, let trailing = debounce.deadline {
            let deadline = min(trailing, routeModel.maximumDeadline ?? trailing)
            do { try await clock.sleep(for: max(.zero, deadline - clock.now)); try Task.checkCancellation() }
            catch { return }
            if debounce.take(at: clock.now) || clock.now >= (routeModel.maximumDeadline ?? trailing) {
                debounce = NetworkEventDebounce()
                break
            }
        }
        await reconcile(); debounceTask = nil
        if !pending.isEmpty, retryAt == nil, running {
            debounceTask = Task { [weak self] in await self?.waitForBatch() }
        }
    }

    private func reconcile() async {
        guard !reconciling, retryAt.map({ clock.now >= $0 }) ?? true else { return }
        reconciling = true; defer { reconciling = false }
        var batch = pending; pending = []
        debounce = NetworkEventDebounce()
        _ = routeModel.takeReconciliation(at: clock.now)
        let route = batch.contains(where: \.isRoute)
        let network = batch.isEmpty || retryAt != nil || route || batch.contains(where: \.isUnderlay)
        if network {
            guard let event = await currentUnderlay(requeue: batch) else { return }
            if await recoveryUnderlay(event) {
                pending = batch + pending; retryAt = clock.now + .seconds(5); return
            }
            do {
                try await controller.networkChanged(trigger: route ? .route : .configuration, underlay: event)
                await controller.monitoringRecovered()
            } catch {
                // A controller operation failure already publishes its own blocking/recovery state.
                pending = batch + pending; await deferRetry(monitorFailure: false); return
            }
            batch.removeAll { $0.isRoute || $0.isUnderlay }
        }
        pending = batch + pending
        if needsRestart {
            retryAt = clock.now + .seconds(5)
        } else if !batch.isEmpty {
            retryAt = await controller.maintenanceState.retryAt ?? clock.now + .seconds(5)
        } else {
            retryAt = nil; retryAttempt = 0
        }
    }

    private func currentUnderlay(requeue batch: [NetworkTrigger]) async -> UnderlayEvent? {
        do {
            let event = try await readUnderlay()
            guard !event.readFailed else { throw DaemonFailure.hostSystem(5) }
            return event
        } catch {
            pending = batch + pending; await failed(); return nil
        }
    }

    private func failed() async {
        await deferRetry(monitorFailure: true)
    }

    private func deferRetry(monitorFailure: Bool) async {
        if monitorFailure {
            await controller.monitoringFailed(); failure()
        }
        let due = clock.now + .seconds([5, 15, 60][min(retryAttempt, 2)])
        retryAt = await max(due, controller.maintenanceState.retryAt ?? due)
        retryAttempt = min(retryAttempt + 1, 3)
    }
}

private extension DaemonNetworkMonitoring {
    func consumeLifecycle(_ event: NetworkTrigger) async -> Bool {
        switch event {
        case let .action(attempt): await apply(attempt); return true
        case let .barrier(id): lifecycleBarriers.removeValue(forKey: id)?.resume(); return true
        case .lifecycle:
            if let streamSink {
                receive(event, sink: streamSink)
            }
            return true
        default: return false
        }
    }

    func observe<Event: Sendable>(
        _ events: AsyncStream<Event>, sink: AsyncStream<NetworkTrigger>.Continuation,
        transform: @escaping @Sendable (Event) -> NetworkTrigger,
    ) -> Task<Void, Never> {
        Task { [weak self] in
            for await event in events {
                guard !Task.isCancelled else { return }
                await self?.receive(transform(event), sink: sink)
            }
            if !Task.isCancelled {
                await self?.receive(.failed, sink: sink)
            }
        }
    }
}

private extension NetworkTrigger {
    var isRoute: Bool {
        if case .route = self {
            true
        } else {
            false
        }
    }

    var isUnderlay: Bool {
        if case .underlay = self {
            true
        } else {
            false
        }
    }
}
