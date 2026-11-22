// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

extension TunnelController {
    /// Publication reads bookkeeping only; policy verification remains owned by the controller tick.
    package func publicationMeasurement(nextSequence: @Sendable () throws -> UInt64) throws -> StatusMeasurement {
        var status = snapshot
        status.activeProfileID = intended?.profileID
        status.operationInFlight = operation != nil
        status.measuredAt = clock.wallNow
        status.measuredAtContinuous = clock.continuousNow
        // One journal read serves every field of the measurement, so the policy, the token and the owner agree.
        let document = journal.snapshot()
        status.policyEnforcing = document.pfPolicy != .disconnected
        status.sequence = try nextSequence()
        let owner = intended?.ownerUID ?? document.protectionOwnerUID
        #if WGEX_LAB_BUILD
            var measurement = StatusMeasurement(
                status: status, ownerUID: owner, journalPolicy: JournalPolicyName(document.pfPolicy), ownerPFToken: document.pfToken,
            )
        #else
            var measurement = StatusMeasurement(status: status, ownerUID: owner, journalPolicy: JournalPolicyName(document.pfPolicy))
        #endif
        measurement.uninstall = document.uninstall?.progress
        return measurement
    }

    package var endpointAddresses: [String] {
        Array(Set(rotation.candidates.values.flatMap { $0.map(\.stringRepresentation) })).sorted()
    }

    package var selectedEndpoints: [PublicKey: Endpoint] {
        var selected: [PublicKey: Endpoint] = [:]
        for (peer, values) in rotation.candidates {
            let index = rotation.indices[peer] ?? 0
            if values.indices.contains(index) {
                selected[peer] = values[index]
            }
        }
        return selected
    }

    package func performResolve(
        _ profile: TunnelProfile, generation: Generation, allowLastGoodOnFailure: Bool = true,
    ) async throws -> [PublicKey: [Endpoint]] {
        var result: [PublicKey: [Endpoint]] = [:]
        snapshot.protectionNote = nil
        rotation.awaitingIPv6 = false
        for peer in profile.peers {
            guard let endpoint = peer.endpoint else { continue }
            let addresses: [String]
            if let literal = try? IPAddressRange(endpoint.host), !endpoint.host.contains("/") {
                addresses = [literal.address]
            } else {
                let cached = journal.snapshot().lastGoodAddresses[endpoint.host] ?? []
                do {
                    let fresh = try await ports.resolver.resolve(host: endpoint.host, underlay: underlay)
                    try check(generation)
                    let preferred = UnderlayResolver.validLiterals(cached).filter { fresh.contains($0) }
                    addresses = preferred + Self.orderCandidates(fresh, prefersIPv6: underlay.ipv6DefaultRouteAvailable)
                        .filter { !preferred.contains($0) }
                } catch {
                    try check(generation)
                    guard allowLastGoodOnFailure, !cached.isEmpty else { throw error }
                    addresses = UnderlayResolver.validLiterals(cached)
                }
                guard !addresses.isEmpty else { throw DaemonFailure.portNoAnswer }
            }
            let reachable = reachableEndpoints(addresses)
            guard !reachable.isEmpty else { continue }
            result[peer.publicKey] = try reachable.map {
                guard let literal = try? IPAddressRange($0), !$0.contains("/") else { throw DaemonFailure.portNoAnswer }
                return try Endpoint(validatingHost: literal.address, port: endpoint.port)
            }
        }
        rotation.awaitingIPv6 = rotation.awaitingIPv6 && result.isEmpty
        guard !result.isEmpty || profile.peers.allSatisfy({ $0.endpoint == nil }) else { throw DaemonFailure.portNoAnswer }
        try check(generation)
        rotation.hosts = Dictionary(uniqueKeysWithValues: profile.peers.compactMap { peer in
            peer.endpoint.map { (peer.publicKey, $0.host) }
        })
        return result
    }

    private func reachableEndpoints(_ addresses: [String]) -> [String] {
        let ordered = Self.orderCandidates(addresses, prefersIPv6: underlay.ipv6DefaultRouteAvailable)
        let reachable = ordered.filter { underlay.ipv6DefaultRouteAvailable || !$0.contains(":") }
        if reachable.isEmpty, !ordered.isEmpty, !underlay.ipv6DefaultRouteAvailable {
            snapshot.protectionNote = .ipv6Unavailable
            rotation.awaitingIPv6 = true
        }
        return reachable
    }

    /// RFC 8305 family interleaving, preserving resolver order within each family and preferring IPv6 only on an IPv6 underlay.
    package static func orderCandidates(_ addresses: [String], prefersIPv6: Bool) -> [String] {
        UnderlayResolver.order(addresses, prefersIPv6: prefersIPv6)
    }

    package func scheduleRetry(_ generation: Generation) {
        let delay = rotation.backoffSeconds; rotation.backoffSeconds = min(60, delay * 2)
        rotation.retryTask = Task { [weak self, clock] in
            do {
                try await clock.sleep(for: .seconds(delay))
                try Task.checkCancellation()
                try await self?.refreshEndpoints(generation: generation)
            } catch {
                if !Task.isCancelled {
                    await self?.retryFailed(generation)
                }
            }
        }
    }

    private func retryFailed(_ generation: Generation) {
        guard generation == self.generation else { return }
        rotation.retryTask = nil
        scheduleRetry(generation)
    }

    public func refreshEndpoints(generation: Generation) async throws {
        try check(generation)
        do { try await maintenance { controller, epoch in try await controller.performRefreshEndpoints(generation: epoch) } }
        catch { await consumeEngineFailure(error, generation: generation); throw error }
    }

    private func performRefreshEndpoints(generation: Generation) async throws {
        guard let intended, let engine = engines[generation] else { return }
        try check(generation)
        // A new primary/service may have different resolvers. Permit bound root DNS there before querying it.
        try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: endpointAddresses), generation: generation)
        await ports.resolver.invalidate()
        let registration = try await registry.profile(intended.profileID, connectionUID: intended.ownerUID)
        let previousCandidates = rotation.candidates, previousIndices = rotation.indices, previousPeers = rotation.handshakePeers,
            previousHosts = rotation.hosts
        let resolved = try await resolve(registration.profile, generation: generation, allowLastGoodOnFailure: true)
        try check(generation)
        // Network change and reconnect re-resolve excluded host names and re-carve the tunnel routes (DEC-087).
        try await refreshExclusions(registration.profile, generation: generation)
        let changed = resolved != rotation.candidates
        let retrying = rotation.retryTask != nil
        rotation.candidates = resolved
        if changed || retrying {
            rotation.indices = resolved.mapValues { _ in 0 }; rotation.handshakePeers = []
        }
        try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: endpointAddresses), generation: generation)
        if changed || retrying {
            do { try await engine.updateEndpoints(selectedEndpoints) }
            catch {
                if generation == self.generation, error == .config {
                    rotation.candidates = previousCandidates; rotation.indices = previousIndices
                    rotation.handshakePeers = previousPeers; rotation.hosts = previousHosts
                }
                throw error
            }
        }
        try check(generation)
        if !changed, !retrying, rotation.candidates.keys.allSatisfy({ rotation.handshakePeers.contains($0) }),
           let identity = resource(generation).identity
        {
            try await applyPolicy(.connected(interfaceName: identity.name, endpoints: endpointAddresses), generation: generation)
            try await verifyOffActor(ProtectionExpectation(
                resources: resource(generation),
                policy: journal.snapshot().pfPolicy,
                engine: engine,
            ))
            try await verifyPolicy(refresh: false)
            try check(generation)
            transition(.active(generation), protection: .protected)
        } else {
            transition(.reasserting(generation, reason: .endpointRotation), protection: .blocked)
        }
        rotation.attemptStarted = clock.now; rotation.retryTask = nil
    }

    public func pathChanged(_ underlay: UnderlaySnapshot, satisfied: Bool) async throws {
        try await requireSecureInstall()
        let epoch = generation
        do { try await maintenance { controller, _ in try await controller.performPathChanged(underlay, satisfied: satisfied) } }
        catch { await consumeEngineFailure(error, generation: epoch); throw error }
    }

    private func performPathChanged(_ underlay: UnderlaySnapshot, satisfied: Bool) async throws {
        self.underlay = underlay
        appliedPathSatisfied = satisfied
        snapshot.health.level = health.updatePath(satisfied ? .satisfied : .unsatisfied).level
        snapshot.record(TunnelEvent(date: clock.wallNow, kind: .pathChanged, generation: generation)); publish()
        guard satisfied else {
            if intended != nil {
                throw DaemonFailure.controllerOperationFailed
            }
            return
        }
        guard let engine = engines[generation] else { return }
        try await engine.bumpSockets(v4: underlay.socketV4, v6: underlay.socketV6)
        if let intended, let identity = resource(generation).identity {
            let registration = try await registry.profile(intended.profileID, connectionUID: intended.ownerUID)
            try await configureChangedUnderlay(registration.profile, identity: identity)
            if journal.snapshot().captiveWindow == nil {
                try await ports.routes.install(resource(generation).routes, generation: generation)
            }
        }
        // Captive windows must retain withdrawn routes and DNS throughout path changes.
        guard journal.snapshot().captiveWindow == nil else { return }
        try await performRefreshEndpoints(generation: generation)
    }
}

public extension TunnelController {
    /// A daemon bookkeeping tick, independent of UI statistics subscriptions. It never resolves successful peers on a timer.
    func tick() async throws {
        publish()
        guard !uninstallFenced else { return } // Inert during and after an uninstall (M05-T07).
        try await requireSecureInstall()
        if needsRecovery || startup.reconciliationPending {
            try await retryStartupOnTick()
            return
        }
        guard operation == nil else { return }
        if let due = maintenanceState.retryAt {
            if clock.now >= due {
                _ = try await retryMaintenanceIfDue()
            } else {
                try await maintenance { controller, _ in
                    if await controller.liveness.shouldVerify(
                        trigger: .periodic,
                        enforcing: controller.journal.snapshot().pfPolicy != .disconnected,
                        now: controller.clock.now,
                    ) {
                        try await controller.verifyPolicy(refresh: true)
                    }
                }
            }
            return
        }
        if let captive = journal.snapshot().captiveWindow {
            if CaptiveWindowModel.isExpired(captive, continuous: clock.now) {
                try await closeCaptiveWindow()
            } else {
                try await maintenance { controller, _ in try await controller.verifyPolicy(refresh: true) }
            }
            return
        }
        let epoch = generation
        do { try await maintenance { controller, _ in try await controller.performTick() } }
        catch { await consumeEngineFailure(error, generation: epoch); throw error }
    }
}

extension TunnelController {
    package func performTick() async throws {
        let epoch = generation
        let before = snapshot
        try await verifyPeriodically(epoch: epoch)
        // Tick publications carry health/policy changes. The dispatcher owns the independent reporting heartbeat.
        guard let engine = engines[generation] else {
            publishIfChanged(from: before)
            return
        }
        let evaluation = health.evaluate()
        snapshot.health.level = evaluation.level
        publishIfChanged(from: before)
        guard rotation.retryTask == nil, let started = rotation.attemptStarted, clock.now - started >= .seconds(10) else { return }
        let pending = rotation.candidates.keys.filter { !rotation.handshakePeers.contains($0) }
        guard !pending.isEmpty else { return }
        try await rotateCandidates(pending, engine: engine, epoch: epoch)
    }

    /// Periodic verification runs on the liveness cadence; a connected engine also gets the full verifier.
    private func verifyPeriodically(epoch: Generation) async throws {
        guard await liveness.shouldVerify(
            trigger: .periodic, enforcing: journal.snapshot().pfPolicy != .disconnected, now: clock.now,
        ) else { return }
        try await verifyPolicy(refresh: true)
        if let engine = engines[epoch], resource(epoch).identity != nil, journal.snapshot().captiveWindow == nil {
            try await verifyOffActor(ProtectionExpectation(
                resources: resource(epoch), policy: journal.snapshot().pfPolicy, engine: engine,
            ))
            try check(epoch)
        }
    }

    /// Advances every peer without a handshake to its next endpoint candidate, or backs off when exhausted.
    private func rotateCandidates(_ pending: [PublicKey], engine: any EngineControlling, epoch: Generation) async throws {
        let previousIndices = rotation.indices
        var exhausted = false
        for peer in pending {
            let next = (rotation.indices[peer] ?? 0) + 1
            if next < (rotation.candidates[peer]?.count ?? 0) {
                rotation.indices[peer] = next
            } else {
                exhausted = true
            }
        }
        if exhausted {
            try await checkpoint(.retryBackoff, generation: generation)
            try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: endpointAddresses), generation: generation)
            transition(.reasserting(generation, reason: .endpointRotation), protection: .blocked)
            scheduleRetry(generation)
            try entry(.retryBackoff, .didApply, generation: generation)
        } else {
            try await checkpoint(.rotateCandidate, generation: generation)
            try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: endpointAddresses), generation: generation)
            transition(.reasserting(generation, reason: .endpointRotation), protection: .blocked)
            do { try await engine.updateEndpoints(selectedEndpoints) }
            catch {
                if epoch == generation, error == .config {
                    rotation.indices = previousIndices
                }
                throw error
            }
            try check(generation); try entry(.rotateCandidate, .didApply, generation: generation)
            rotation.attemptStarted = clock.now
        }
    }

    private func publishIfChanged(from previous: TunnelStatus) {
        if !snapshot.hasSameState(as: previous) {
            publish()
        }
    }
}

package extension TunnelController {
    /// Caller cancellation never completes this wait or relinquishes the serial slot.
    func boundedResult(_ task: Task<Void, any Error>) async throws {
        let id = operationID
        let result: Result<Void, any Error> = await withCheckedContinuation { continuation in
            let completion = ControllerCompletion(continuation)
            let deadline = Task { [weak self, operationClock] in
                do {
                    try await operationClock.sleep(for: .seconds(60)); try Task.checkCancellation()
                    guard let waiter = completion.take() else { return }
                    // Once the deadline wins, only this task owns expiry and the continuation.
                    let expired = await self?.operationExpired(id: id) ?? true
                    // A stage that handed its slot over inside its own turn has ended its work: its deadline is no expiry, and
                    // the stage's own result (its task returns at once) is what the waiter receives (M1-29 R1).
                    if !expired, await self?.deadlineFollowedHandOver(of: id) == true {
                        await waiter.resume(returning: task.result)
                        return
                    }
                    waiter.resume(returning: .failure(DaemonFailure.controllerOperationFailed))
                } catch { /* The completed operation cancels its own deadline. */ }
            }
            Task {
                let result = await task.result
                guard let waiter = completion.take() else { return }
                deadline.cancel(); waiter.resume(returning: result)
            }
        }
        try result.get()
    }

    /// The watchdog's only publication. pf holds, or is reloaded with, the blocking policy first; protection is claimed
    /// `blocked` only when the policy port measured it (as `publishStartFailure` does), never from the expiry alone. The
    /// abandoned generation's utun and addresses stay journalled: `needsRecovery` makes the next reconciliation inspect and
    /// remove them before any new start. An engine whose creation was still in flight is shut down when that stale call
    /// returns (`startEngine`). An engine abandoned after it was created stays up, with its utun, routes and DNS key,
    /// behind the pf `.error` the expiry loads, until the next `reconcileStartupResources` shuts every engine down; that
    /// reconciliation now runs behind the 5/15/60 s backoff. Returns whether it ended the operation: false when `id` is no
    /// longer the serial slot (the stage handed over, or a control replaced it), in which case nothing changed.
    @discardableResult
    func operationExpired(id: UUID) async -> Bool {
        guard operation != nil, operationID == id else { return false }
        operationLog("operation expired, last step=\(lastStep?.rawValue ?? "none")")
        if let stoppingProfile, stoppingProfile.generation == generation {
            pendingTeardownProfileID = stoppingProfile.id
        }
        needsRecovery = true
        abandonedGenerations.insert(generation)
        abandonedGenerations.formUnion(journal.snapshot().resources.map(\.generation))
        operation?.cancel(); operation = nil
        // The abandoned stage's reserved boot start dies with it; the slot and the reservation are cleared together.
        startup.bootStart = nil
        cancelBackgroundWork()
        startup.expiredControlID = startup.controlID
        startup.controlID = UUID()
        snapshot.recoveryFailureReason = .reconciliationFailed
        let blocking = intended != nil || settings.lockdown
        // Every fence above is already in place, so this read can suspend safely. Protection is claimed `blocked` from a
        // measurement only: the interim status never says `unknown` while pf measures blocked, and never says `blocked`
        // when it does not.
        let expired = generation
        var measuredBlocked = false
        if blocking {
            measuredBlocked = await ports.policy.verification() == .blocked
        }
        guard expired == generation else { return true }
        transition(
            .failed(.backendUnavailable, blockedByPolicy: measuredBlocked, needsSecrets: false),
            protection: measuredBlocked ? .blocked : .unknown,
        )
        var emergencyGeneration = generation
        do {
            let epoch = try reserve(intent: intended)
            emergencyGeneration = epoch
            try withdrawCaptiveException()
            snapshot.recoveryFailureReason = .reconciliationFailed
            try await applyPolicy(failurePolicy, generation: epoch)
            guard epoch == generation else { return true }
            measuredBlocked = false
            if blocking {
                measuredBlocked = await ports.policy.verification() == .blocked
            }
        } catch { measuredBlocked = false /* Unknown is retained even if the emergency policy cannot be loaded. */ }
        guard emergencyGeneration == generation else { return true }
        transition(
            .failed(.backendUnavailable, blockedByPolicy: measuredBlocked, needsSecrets: false),
            protection: measuredBlocked ? .blocked : .unknown,
        )
        return true
    }

    /// Whether `id` was the slot of a stage that has since handed its work over (the boot start's task took the slot inside
    /// the stage's own turn). Says so once, in fixed words, so a run can tell this from an expiry.
    func deadlineFollowedHandOver(of id: UUID) -> Bool {
        guard startup.handedOver?.stage1Slot == id else { return false }
        operationLog("startup stage deadline fired after its hand-over; not an expiry")
        return true
    }

    func maintenanceFailed(generation epoch: Generation, reason: RecoveryFailureReason = .reconciliationFailed) async {
        scheduleMaintenanceRetry()
        let note = snapshot.protectionNote ?? .verificationFailed
        do {
            try withdrawCaptiveException()
            try await applyPolicy(failurePolicy, generation: epoch)
            guard epoch == generation else { return }
            snapshot.recoveryFailureReason = reason
            snapshot.protectionNote = note
            transition(
                .failed(.backendUnavailable, blockedByPolicy: intended != nil || settings.lockdown, needsSecrets: false),
                protection: failurePolicy == .disconnected ? .unprotected : .blocked,
            )
        } catch {
            guard epoch == generation else { return }
            snapshot.recoveryFailureReason = .blockingPolicyFailed
            transition(.failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false), protection: .unknown)
        }
    }

    func scheduleMaintenanceRetry() {
        resetMaintenanceBackoffIfStable()
        maintenanceState.stableActiveSince = nil
        let delay = [5, 15, 60][min(maintenanceState.retryAttempt, 2)]
        maintenanceState.retryAttempt = min(maintenanceState.retryAttempt + 1, 3)
        maintenanceState.retryAt = clock.now + .seconds(delay)
    }

    func retryMaintenanceIfDue() async throws -> Bool {
        guard let due = maintenanceState.retryAt else { return false }
        guard clock.now >= due else { return true }
        let rollbackPending = journal.snapshot().cutover?.rollbackPending == true
        if engines[generation] == nil, let intent = intended, appliedPathSatisfied, !rollbackPending {
            try await restartFailedIntent(intent)
            return true
        }
        try await maintenance { controller, epoch in
            guard controller.appliedPathSatisfied else { throw DaemonFailure.controllerOperationFailed }
            if let engine = controller.engines[epoch], let identity = controller.resource(epoch).identity {
                if let intent = controller.intended {
                    let registration = try await controller.registry.profile(intent.profileID, connectionUID: intent.ownerUID)
                    try controller.check(epoch)
                    try await controller.configureChangedUnderlay(registration.profile, identity: identity)
                }
                let resources = controller.resource(epoch)
                try await controller.applyPolicy(.connecting(
                    resolvers: controller.underlay.resolvers,
                    endpoints: controller.endpointAddresses,
                ), generation: epoch)
                controller.transition(.reasserting(epoch, reason: .pathChanged), protection: .blocked)
                try await controller.ports.routes.install(resources.routes, generation: epoch)
                try controller.check(epoch)
                if let dns = resources.dns {
                    try await controller.ports.dns.apply(dns, generation: epoch)
                }
                try controller.check(epoch)
                try await controller.applyPolicy(.connected(
                    interfaceName: identity.name,
                    endpoints: controller.endpointAddresses,
                ), generation: epoch)
                try await controller.verifyOffActor(.init(
                    resources: resources,
                    policy: controller.journal.snapshot().pfPolicy,
                    engine: engine,
                ))
                try controller.check(epoch)
                if controller.snapshot.protectionNote == .verificationFailed || controller.snapshot.protectionNote == .canaryFailed {
                    controller.snapshot.protectionNote = nil
                }
                controller.transition(.active(epoch), protection: .protected)
            } else {
                try await controller.applyPolicy(controller.failurePolicy, generation: epoch)
                controller.snapshot.recoveryFailureReason = nil
                controller.transition(.idle, protection: controller.failurePolicy == .disconnected ? .unprotected : .blocked)
            }
            controller.maintenanceState.retryAt = nil
            controller.snapshot.recoveryFailureReason = nil
        }
        return true
    }

    private func restartFailedIntent(_ intent: TunnelIntent) async throws {
        // A failed start has already rolled back its generation. Re-drive the persisted
        // intent through the normal start path, including resolution, resource fencing and secrets.
        let epoch = generation
        await ports.resolver.invalidate()
        guard generation == epoch, intended == intent, operation == nil else { return }
        maintenanceState.retryAt = nil
        transition(.reasserting(generation, reason: .pathChanged), protection: snapshot.protection)
        do {
            _ = try await restart(intent, expectedGeneration: epoch)
        } catch {
            if generation == epoch, intended == intent, maintenanceState.retryAt == nil {
                scheduleMaintenanceRetry()
            }
            throw error
        }
    }

    func retryStartupOnTick() async throws {
        guard operation == nil else { return }
        if let due = startup.tickRetryAt, clock.now < due {
            try await verifyRecoveryProtection()
            return
        }
        try await reconcileAtStartup()
    }

    func requestStartupRetry() {
        guard let retry = startup.retry else { return }
        Task { await retry() }
    }
}

/// The continuation has exactly one owner, even when completion and deadline race.
package final class ControllerCompletion<Value: Sendable>: Sendable {
    private let continuation: Mutex<CheckedContinuation<Result<Value, any Error>, Never>?>
    package init(_ continuation: CheckedContinuation<Result<Value, any Error>, Never>) {
        self.continuation = Mutex(continuation)
    }

    package func take() -> CheckedContinuation<Result<Value, any Error>, Never>? {
        continuation.withLock { value in
            let result = value; value = nil; return result
        }
    }
}

/// Watchdog time excludes system sleep; captive expiry deliberately retains the continuous clock.
package struct SuspendingDaemonClock: DaemonClock {
    private let origin = SuspendingClock.now
    package var now: Duration {
        origin.duration(to: SuspendingClock.now)
    }

    package var wallNow: Date {
        Date()
    }

    package func sleep(for duration: Duration) async throws {
        try await SuspendingClock().sleep(for: duration)
    }
}

package extension TunnelController {
    /// The entire peer list shares twelve seconds of awake time, leaving time to roll back before the 30 s client deadline.
    func resolve(
        _ profile: TunnelProfile, generation: Generation, allowLastGoodOnFailure: Bool = true,
    ) async throws -> [PublicKey: [Endpoint]] {
        let task = Task { try await performResolve(profile, generation: generation, allowLastGoodOnFailure: allowLastGoodOnFailure) }
        let result: Result<[PublicKey: [Endpoint]], any Error> = await withCheckedContinuation { continuation in
            let completion = ControllerCompletion(continuation)
            let deadline = Task { [operationClock] in
                do {
                    try await operationClock.sleep(for: .seconds(12)); try Task.checkCancellation()
                    guard let waiter = completion.take() else { return }
                    task.cancel(); waiter.resume(returning: .failure(DaemonFailure.portTimedOut))
                } catch { /* A completed resolution cancels this deadline. */ }
            }
            Task {
                let result = await task.result
                guard let waiter = completion.take() else { return }
                deadline.cancel(); waiter.resume(returning: result)
            }
        }
        do { return try result.get() }
        catch {
            if generation == self.generation {
                snapshot.recoveryFailureReason = .resolverUnavailable
            }
            throw error
        }
    }
}
