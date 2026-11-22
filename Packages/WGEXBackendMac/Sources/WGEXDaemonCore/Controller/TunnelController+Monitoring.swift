// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public extension TunnelController {
    /// Notification adapters wait for an in-flight lifecycle transaction, then enter the same serial slot.
    func networkChanged(trigger: ProtectionTrigger, underlay event: UnderlayEvent? = nil) async throws {
        guard !uninstallFenced else { // Inert during and after an uninstall (M05-T07); the event is kept (M05-T16).
            recordFencedUnderlay(event); return
        }
        // A path change is an on-demand input from its receipt: no decision taken before it reaches the lifecycle.
        if event != nil {
            onDemandInputReceived()
        }
        defer {
            if event != nil {
                onDemandInputApplied(.inputSettled)
            }
        }
        try await requireSecureInstall()
        if let event, try await applyUnderlay(event) {
            return
        }
        guard await liveness.shouldVerify(
            trigger: trigger, enforcing: journal.snapshot().pfPolicy != .disconnected, now: clock.now,
        ) else { return }
        await drainLifecycle()
        if maintenanceState.retryAt != nil {
            return
        }
        try await maintenance { controller, epoch in
            try await controller.verifyPolicy(refresh: true)
            guard controller.journal.snapshot().captiveWindow == nil,
                  let engine = controller.engines[epoch], controller.resource(epoch).identity != nil else { return }
            let resources = controller.resource(epoch)
            // Install is ownership-checked and idempotent; foreign replacement is a failure, never a takeover.
            try await controller.ports.routes.install(resources.routes, generation: epoch)
            try controller.check(epoch)
            if let dns = resources.dns {
                do { try await controller.ports.dns.verify(resources) }
                catch { try await controller.ports.dns.apply(dns, generation: epoch) }
            }
            try await controller.verifyOffActor(ProtectionExpectation(
                resources: resources, policy: controller.journal.snapshot().pfPolicy, engine: engine,
            ))
            try controller.check(epoch)
            if case .active = controller.snapshot.phase {
                controller.transition(.active(epoch), protection: .protected)
            }
        }
    }

    private func applyUnderlay(_ event: UnderlayEvent) async throws -> Bool {
        await drainLifecycle()
        let restored = restoresUnderlay(event)
        underlayMTU = event.mtu
        if restored, let due = maintenanceState.retryAt {
            maintenanceState.retryAttempt = 0; maintenanceState.retryAt = min(due, clock.now)
        }
        guard event.snapshot != underlay || event.mtu != appliedUnderlayMTU || event.satisfied != appliedPathSatisfied else { return false }
        appliedUnderlayMTU = event.mtu; appliedPathSatisfied = event.satisfied
        defer { scheduleOnDemand(.underlay) }
        try await pathChanged(event.snapshot, satisfied: event.satisfied)
        if restored {
            _ = try await retryMaintenanceIfDue()
        }
        return true
    }

    /// Applies power observations on the serial consumer and skips superseded observations at entry.
    func powerChanged(_ event: PowerEvent, isCurrent: @escaping @Sendable () -> Bool = { true }) async throws {
        guard !uninstallFenced else { return }
        guard event != .sleep else {
            var ignored = false
            return try await applyPower(event, isCurrent: isCurrent, woke: &ignored)
        }
        // Wake is an on-demand input from its receipt; it invalidates only once it is current.
        onDemandInputReceived()
        var woke = false
        defer { onDemandInputApplied(woke ? .wake : .inputSettled) }
        try await applyPower(event, isCurrent: isCurrent, woke: &woke)
    }

    private func applyPower(_ event: PowerEvent, isCurrent: @escaping @Sendable () -> Bool, woke: inout Bool) async throws {
        let receivedAt = clock.now
        let wallReceivedAt = clock.wallNow
        try await requireSecureInstall()
        await drainLifecycle()
        guard isCurrent() else { return }
        if event == .sleep {
            powerModel.sleep(at: receivedAt); return
        }
        woke = true
        if let window = journal.snapshot().captiveWindow, CaptiveWindowModel.isExpired(window, continuous: clock.now) {
            try await closeCaptiveWindow()
        }
        let decision = powerModel.wake(at: receivedAt, wallNow: wallReceivedAt, lastHandshake: snapshot.health.lastHandshake)
        try await maintenance { controller, epoch in
            guard isCurrent() else { return }
            guard let engine = controller.engines[epoch] else {
                if controller.journal.snapshot().pfPolicy != .disconnected {
                    try await controller.verifyPolicy(refresh: true)
                }
                return
            }
            try await engine.bumpSockets(v4: controller.underlay.socketV4, v6: controller.underlay.socketV6)
            if decision.forceHandshake {
                controller.rotation.handshakePeers = []; controller.rotation.attemptStarted = controller.clock.now
                try await engine.forceHandshake()
                if controller.journal.snapshot().captiveWindow == nil {
                    try await controller.applyPolicy(.connecting(
                        resolvers: controller.underlay.resolvers,
                        endpoints: controller.endpointAddresses,
                    ), generation: epoch)
                    controller.transition(.reasserting(epoch, reason: .wake), protection: .blocked)
                }
            }
            try await controller.verifyPolicy(refresh: true)
            if controller.journal.snapshot().captiveWindow == nil {
                let resources = controller.resource(epoch)
                try await controller.ports.routes.install(resources.routes, generation: epoch)
                if let dns = resources.dns {
                    try await controller.ports.dns.apply(dns, generation: epoch)
                }
                try await controller.verifyOffActor(ProtectionExpectation(
                    resources: resources, policy: controller.journal.snapshot().pfPolicy, engine: engine,
                ))
            }
        }
    }

    /// Commits a console observation only after its decision and durable logout reservation succeed.
    func consoleUserChanged(_ uid: UInt32?, isCurrent: @escaping @Sendable () -> Bool = { true }) async throws {
        guard isCurrent(), !uninstallFenced else { return }
        onDemandInputReceived()
        defer { onDemandInputApplied(.consoleChanged) }
        consoleObservationRevision &+= 1
        let revision = consoleObservationRevision
        try await requireSecureInstall()
        await drainLifecycle()
        guard isCurrent(), revision == consoleObservationRevision else { return }
        var next = LoginSessionMonitorModel(consoleUID: uid == 0 ? nil : uid)
        guard let intent = intended else { loginModel = next; consoleSnapshotReceived = true; return }
        if !consoleWasOwned(by: intent.ownerUID) {
            loginModel = next; consoleSnapshotReceived = true; return
        }
        guard !needsRecovery else { throw DaemonFailure.controllerRecoveryRequired }
        let record = try await registry.registrationForStart(intent.profileID, connectionUID: intent.ownerUID)
        // This is the last await before reserving teardown. New receipt and direct controller calls both fence it.
        guard isCurrent(), revision == consoleObservationRevision, intended == intent else { return }
        guard operation == nil else { throw DaemonFailure.controllerOperationFailed }
        let boot = record.startBeforeLoginOverride ?? record.registration.profile.macOptions.startBeforeLogin
        guard next.receive(uid, ownerUID: intent.ownerUID, startBeforeLogin: boot) else {
            loginModel = next; consoleSnapshotReceived = true; return
        }
        let allocated = try reserve(intent: intent)
        try journal.mutate(generation: allocated) { $0.loginSuspended = true }
        loginModel = next; consoleSnapshotReceived = true
        // Keep durable intent and secrets; logout without lockdown deliberately leaves traffic unprotected (ADR-026).
        intended = nil
        cancelBackgroundWork()
        let task = Task { [self] in
            try await performStop(profileID: intent.profileID, reason: .logout, explicit: false, generation: allocated)
        }
        operation = task
        try await awaitOperation(task, generation: allocated)
    }

    private func consoleWasOwned(by uid: UInt32) -> Bool {
        consoleSnapshotReceived && loginModel.consoleUID == uid
    }

    package func restoresUnderlay(_ event: UnderlayEvent, previous: UnderlayEvent? = nil) -> Bool {
        UnderlayRestoration.isRestored(
            event, previous: previous ?? UnderlayEvent(snapshot: underlay, satisfied: appliedPathSatisfied),
            awaitingIPv6: rotation.awaitingIPv6,
        )
    }

    package func drainLifecycle() async {
        while let operation {
            let slot = operationID
            try? await boundedResult(operation)
            if operationID == slot {
                self.operation = nil
            }
        }
    }

    /// Clears only the monitor-owned failure after a successful read and reconciliation.
    func monitoringRecovered() async {
        guard protectionFailureReason == Self.monitorFailureMessage else { return }
        protectionFailureReason = nil
        switch await ports.policy.verification() {
        case .protected:
            if case .active = snapshot.phase {
                snapshot.protection = .protected
            }
        case .blocked: snapshot.protection = .blocked
        case .unprotected: snapshot.protection = .unprotected
        default: break
        }
        publish()
    }

    private static var monitorFailureMessage: String {
        "WGEX cannot verify network changes. Restart WGEX."
    }

    func monitoringFailed() {
        protectionFailureReason = Self.monitorFailureMessage
        snapshot.protection = .unknown; publish()
    }
}

extension TunnelController {
    /// Engine events drive health; engine log lines go only to the redacting diagnostics ring of `profileID` (the Mac log
    /// view's tunnel log). Both loops end with the engine's streams or when `eventTask` is cancelled.
    package func observeEvents(_ engine: any EngineControlling, generation: Generation, profileID: UUID? = nil) {
        let diagnostics = diagnostics
        eventTask = Task { [weak self] in
            await withDiscardingTaskGroup { group in
                group.addTask {
                    for await line in await engine.logs {
                        guard !Task.isCancelled else { break }
                        diagnostics.recordEngine(line.message, date: line.date, profileID: profileID)
                    }
                }
                for await event in await engine.events {
                    guard !Task.isCancelled else { break }
                    await self?.consume(event, generation: generation)
                }
                group.cancelAll()
            }
        }
    }

    /// Also serves as the deterministic host seam for engine callback delivery.
    public func consume(_ event: EngineEvent, generation: Generation) async {
        guard generation == self.generation, engines[generation] != nil else { return }
        if case let .engine(lifecycle) = event {
            await consumeLifecycle(lifecycle, generation: generation)
            return
        }
        if operation != nil {
            pendingEvents.append((event, generation)); pendingEvents = Array(pendingEvents.suffix(32)); return
        }
        let (evaluation, kind) = evaluate(event)
        if case let .handshakeCompleted(peer, _) = event {
            powerModel.handshakeCompleted()
            if let endpoint = selectedEndpoints[peer], let host = rotation.hosts[peer],
               (try? IPAddressRange(host)) == nil
            {
                try? journal.mutate(generation: generation) { document in
                    document.lastGoodAddresses[host] = Array(([endpoint.host] + (document.lastGoodAddresses[host] ?? [])
                            .filter { $0 != endpoint.host }).prefix(32))
                }
            }
        }
        snapshot.health = TunnelHealth(level: evaluation.level, lastHandshake: evaluation.lastHandshake, rxRate: 0, txRate: 0)
        if let kind {
            snapshot.record(TunnelEvent(date: clock.wallNow, kind: kind, generation: generation))
        }
        if evaluation.requests.contains(.forceHandshake) {
            do { try await engines[generation]?.forceHandshake() }
            catch { await consumeEngineFailure(error, generation: generation) }
        }
        try? await restoreAfterHandshake(generation)
        guard generation == self.generation else { return }
        publish()
    }

    private func evaluate(_ event: EngineEvent) -> (HealthEvaluation, TunnelEvent.Kind?) {
        let evaluation: HealthEvaluation
        let kind: TunnelEvent.Kind?
        switch event {
        case .engine:
            evaluation = health.evaluate(); kind = nil // Lifecycle is consumed before health queuing.
        case let .handshakeCompleted(peer, at):
            rotation.handshakePeers.insert(peer); rotation.backoffSeconds = 5
            if rotation.candidates.keys.allSatisfy({ rotation.handshakePeers.contains($0) }) {
                rotation.retryTask?.cancel(); rotation.retryTask = nil
            }
            evaluation = health.consume(.handshakeCompleted(at: at)); kind = .handshakeCompleted
        case let .txWithoutRx(since):
            let age = max(0, clock.wallNow.timeIntervalSince(since))
            evaluation = health.consume(.txWithoutRx(since: clock.now - .seconds(age))); kind = .txWithoutRx
            if evaluation.requests.contains(.forceHandshake) {
                rotation.handshakePeers = []; rotation.attemptStarted = clock.now
            }
        case .rx:
            evaluation = health.consume(.rx); kind = nil
        case .endpointChanged:
            evaluation = health.evaluate(); kind = .endpointChanged
        case let .transport(event):
            switch event {
            case .carrierConnected: evaluation = health.updateCarrier(.connected)
            case .carrierDisconnected, .authFailed, .certificateMismatch: evaluation = health.updateCarrier(.disconnected)
            }
            kind = nil
        }
        return (evaluation, kind)
    }

    private func consumeLifecycle(_ event: EngineLifecycleEvent, generation: Generation) async {
        let failure: TunnelError
        switch event {
        case .deviceClosed: failure = .engine(code: -9)
        case .socketsBumped(ok: false): failure = .engine(code: -5)
        case .configRestored:
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.configurationRestored()
            #endif
            return // The previous configuration is still live; never publish the rejected desired configuration.
        case .socketsBumped(ok: true): return
        }
        // Fence immediately, before any await: neither queued callbacks nor a suspended start may publish active.
        guard let retired = engines.removeValue(forKey: generation) else { return }
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        snapshot.protection = .unknown; publish()
        let fenced: Generation
        do { fenced = try reserve(intent: intended) }
        catch {
            await retired.shutdown()
            if generation == self.generation {
                needsRecovery = true
                transition(.failed(failure, blockedByPolicy: false, needsSecrets: false), protection: .unknown)
            }
            return
        }
        let task = Task<Void, any Error> { [self] in
            if let previous {
                _ = await previous.result
            }
            // A superseding user operation owns cleanup now, but this handle is always retired exactly once.
            guard fenced == self.generation else { await retired.shutdown(); return }
            _ = await failStart(failure, generation: fenced, cleanupGeneration: generation, retiredEngine: retired)
        }
        operation = task
        try? await awaitOperation(task, generation: fenced)
    }

    package func consumeEngineFailure(_ error: any Error, generation: Generation) async {
        guard (error as? EngineError) == .deviceClosed, generation == self.generation, engines[generation] != nil else { return }
        await consumeLifecycle(.deviceClosed(.unknown), generation: generation)
    }

    private func restoreAfterHandshake(_ generation: Generation) async throws {
        guard generation == self.generation, !powerModel.awaitingHandshake else { return }
        if case .reasserting = snapshot.phase, rotation.candidates.keys.allSatisfy({ rotation.handshakePeers.contains($0) }) {
            do {
                try await maintenance { controller, epoch in
                    guard let identity = controller.resource(epoch).identity, let engine = controller.engines[epoch] else {
                        throw DaemonFailure.controllerNotActive
                    }
                    try await controller.applyPolicy(
                        .connected(interfaceName: identity.name, endpoints: controller.endpointAddresses),
                        generation: epoch,
                    )
                    try await controller.verifyOffActor(ProtectionExpectation(
                        resources: controller.resource(epoch), policy: controller.journal.snapshot().pfPolicy, engine: engine,
                    ))
                    try await controller.verifyPolicy(refresh: false)
                    try controller.check(epoch)
                    controller.recordPolicyVerification()
                    controller.transition(.active(epoch), protection: .protected)
                }
            } catch { /* Maintenance publishes a blocking failure or unknown protection. */ }
        }
    }
}
