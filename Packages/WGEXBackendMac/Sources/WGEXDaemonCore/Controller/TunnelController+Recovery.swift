// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public extension TunnelController {
    package func requireStartupAdmission() throws {
        guard acceptingRequests, !Task.isCancelled else { throw CancellationError() }
    }

    /// Run before accepting intents after process launch. This method performs no system work without injected ports.
    ///
    /// Two serial operations, each under its own 60 s watchdog (M1-25): reconciliation proper, then the boot-intent
    /// start. A slow boot therefore cannot charge the time reconciliation took to the start. The hand-over happens inside
    /// the reconciliation task: it creates the start's task and assigns the serial slot in one actor turn, so the slot
    /// never holds a completed task, and never sits empty, while a boot start is pending (a concurrent drain or the
    /// recovery heartbeat finds it occupied). `needsRecovery` stays true until the start ends, so app requests meet the
    /// same recovery admission as during reconciliation, and pf holds the blocking policy with the intent set across the
    /// hand-over (`ensureStartupProtection` ran before it).
    func reconcileAtStartup() async throws {
        guard !uninstallFenced else { return } // No restore during or after an uninstall (M05-T07).
        try requireStartupAdmission()
        // The stage's admission, taken before its first await through the common lifetime wrapper: its boot claim, purge
        // replay and reservations commit under it, so a command received after it is newer than every one of them, and
        // whatever the stage leaves running after it ends (an expired stage) can no longer commit.
        try await withCommand(.recovery, profile: nil, input: false) { admission in
            if try await reconcileCutoverAtStartup() {
                return
            }
            await drainLifecycle()
            try requireStartupAdmission()
            startup.failurePublishedFor = nil
            try journal.mutate(generation: nil) { $0.cleanShutdownAt = nil }
            needsRecovery = true
            startup.bootStart = nil; startup.handedOver = nil
            let controlID = startup.controlID
            let lineage = admission.lineage
            let reconciliation = Task { [self] in
                // A stage that ends without handing a start over releases its own reservation, and only its own.
                defer { releaseBootStart(of: controlID, unlessHandedOver: true) }
                try requireStartupStage(controlID)
                try await performReconciliation(controlID: controlID, admission: readmit(lineage))
                try requireStartupStage(controlID)
                try handOverBootStart(controlID: controlID)
            }
            try await runStartupStage(reconciliation, controlID: controlID)
            // The hand-over is read from the record it left, not from `bootStart`: a start that ends before this waiter resumes
            // has already cleared its reservation, and it must still be observed here, so that a fast failure takes
            // `recoveryFailed` and the backoff and clears the slot, instead of the runtime declaring recovery over with the
            // finished task in the slot (M1-30 NF1).
            guard let handedOver = startup.handedOver, handedOver.controlID == controlID else { return }
            try await runStartupStage(handedOver.stage.task, controlID: controlID, assignedSlot: handedOver.stage.slot)
        }
    }

    package func requireStartupStage(_ controlID: UUID) throws {
        try requireStartupAdmission()
        guard startup.controlID == controlID else { throw CancellationError() }
    }

    private func releaseBootStart(of controlID: UUID, unlessHandedOver: Bool = false) {
        guard let boot = startup.bootStart, boot.controlID == controlID, !unlessHandedOver || boot.stage == nil else { return }
        startup.bootStart = nil
    }

    /// Runs inside the reconciliation task with no await: either the reconciliation commits (no boot start), or the boot
    /// start's task becomes the serial slot's occupant before the reconciliation task returns. A reservation made by a
    /// stage that is no longer current is never handed over.
    private func handOverBootStart(controlID: UUID) throws {
        guard var boot = startup.bootStart else {
            commitReconciliation()
            return
        }
        // Unreachable today: the caller checked the stage's identity in this same turn, and the reservation was made by this
        // stage in the same actor turn chain (no await between `reserve` and here), so identity and generation match. Kept as a
        // fence for a change that puts an await between them; debug builds and the test suites trap if it is ever taken.
        guard boot.controlID == controlID, boot.generation == generation else {
            assertionFailure("a boot reservation is handed over only by the stage, and in the turn, that made it")
            throw CancellationError()
        }
        let start = Task { [self] in
            defer { releaseBootStart(of: controlID) }
            try await steps.before(.applyIntents, generation: boot.generation)
            try check(boot.generation)
            noteStepBegin(.applyIntents)
            do { try await performStart(boot.registration, payload: nil, generation: boot.generation) }
            catch DaemonFailure.controllerSecretsUnavailable { /* Reconciliation is complete; an app may provide missing secrets. */ }
            guard startup.controlID == controlID, !Task.isCancelled else { throw CancellationError() }
            try entry(.applyIntents, .didApply, generation: boot.generation)
            commitReconciliation()
        }
        let stage1Slot = operationID
        operation = start
        let stage = PendingBootStart.Stage(task: start, slot: operationID)
        boot.stage = stage
        startup.bootStart = boot
        startup.handedOver = HandedOverStage(controlID: controlID, stage: stage, stage1Slot: stage1Slot)
    }

    /// Runs one startup stage as the serial operation. A stage that expired is told apart from one a control interrupted.
    /// `assignedSlot` is the slot a hand-over already gave the stage's task inside the previous stage.
    private func runStartupStage(_ task: Task<Void, any Error>, controlID: UUID, assignedSlot: UUID? = nil) async throws {
        let slot: UUID
        if let assignedSlot {
            // Reaches only the stage's own task and slot. A control rotates the identity (first test); a drain that cleared
            // the slot without one (second) would end in the same `interruption` through `boundedResult`'s failure below, so
            // this is the earlier exit that arms no watchdog on a stage that no longer owns the slot, not a distinct outcome.
            guard startup.controlID == controlID, operationID == assignedSlot, acceptingRequests, !Task.isCancelled else {
                task.cancel()
                throw interruption(of: controlID)
            }
            slot = assignedSlot
        } else {
            operation = task
            slot = operationID
        }
        do { try await boundedResult(task) }
        catch {
            releaseBootStart(of: controlID)
            guard startup.controlID == controlID, !(error is CancellationError) else { throw interruption(of: controlID) }
            if operationID == slot {
                operation = nil
            }
            let reason = classifyStartupFailure(error)
            try await recoveryFailed(reason, expectedControlID: controlID)
            let delay = [5, 15, 60][min(startup.tickRetryAttempt, 2)]
            startup.tickRetryAttempt += 1; startup.tickRetryAt = clock.now + .seconds(delay)
            throw DaemonFailure.startup(reason)
        }
        guard startup.controlID == controlID else { throw interruption(of: controlID) }
        // A boot start follows: its task already holds the slot, so nothing below may clear it.
        guard assignedSlot != nil || startup.bootStart?.stage == nil else { return }
        if operationID == slot {
            operation = nil
        }
        let events = pendingEvents; pendingEvents = []
        for (event, epoch) in events {
            await consume(event, generation: epoch)
        }
    }

    /// Expiry has already published its measured state and must back off: the runtime's requeue waits 5, 15, 60 s, and a
    /// tick-driven retry waits the same schedule through `tickRetryAt`, which the next committed reconciliation resets.
    /// Any other interruption (a stop, a settings change, a newer start) requeues at once.
    package func interruption(of controlID: UUID) -> any Error {
        guard startup.expiredControlID == controlID else { return CancellationError() }
        let delay = [5, 15, 60][min(startup.tickRetryAttempt, 2)]
        startup.tickRetryAttempt += 1; startup.tickRetryAt = clock.now + .seconds(delay)
        return StartupOperationExpired()
    }

    /// The connection adapter applies the authorisation table before calling this method.
    func setGlobalSettings(_ settings: MacGlobalSettings, connectionUID: UInt32? = nil) async throws {
        guard !settings.lockdown || !cutoverIsArmed else { throw DaemonFailure(code: .slotRefused) }
        guard (1 ... 3600).contains(settings.captiveWindowSeconds) else { throw DaemonFailure.controllerInvalidConfiguration }
        if needsRecovery {
            return try await setRecoverySettings(settings, uid: connectionUID)
        }
        let tightening = settings.lockdown && !self.settings.lockdown
            && AuthorisationTable.recoveryAllows(from: self.settings, to: settings)
        if tightening {
            if await secureInstall.status().state != .verified, startup.installWasVerified {
                startup.secureInstallRegressed = true
            }
        } else {
            try await requireSecureInstall()
        }
        try await cutoverAdmittedMaintenance { controller, _ in
            try await controller.performSetGlobalSettings(settings, connectionUID: connectionUID)
        }
    }

    private func performSetGlobalSettings(_ settings: MacGlobalSettings, connectionUID: UInt32?) async throws -> Bool {
        try requireNoUninstall() // The commit boundary: the secure-install read above may have suspended across an uninstall.
        guard !settings.lockdown || !cutoverIsArmed else { return false }
        guard (1 ... 3600).contains(settings.captiveWindowSeconds) else { throw DaemonFailure.controllerInvalidConfiguration }
        self.settings = settings
        try journal.mutate(generation: generation) {
            $0.settings = settings
            if $0.protectionOwnerUID == nil {
                $0.protectionOwnerUID = connectionUID
            }
        }
        let current = journal.snapshot().pfPolicy
        let policy: PacketFilterPolicy = startup.secureInstallRegressed ? failurePolicy
            : (intended == nil ? (settings.lockdown ? .lockdown : .disconnected) : current)
        if policy != .disconnected {
            try await acquireToken(generation)
        }
        try await applyPolicy(policy, generation: generation)
        if policy == .disconnected, let token = journal.snapshot().pfToken {
            try await ports.policy.releaseToken(token)
            try journal.mutate(generation: generation) { $0.pfToken = nil }
        }
        snapshot.protection = policy == .disconnected ? .unprotected : (policy == .lockdown ? .blocked : snapshot.protection)
        publish()
        return true
    }
}

public extension TunnelController {
    /// Registers the runtime's single recovery owner; repairs never call reconciliation directly.
    func setStartupRetry(_ action: @escaping @Sendable () async -> Void) {
        startup.retry = action
    }

    /// Registers the runtime's startup re-entry, run when a fresh install lifts the uninstall fence (M05-T18).
    func setStartupResume(_ action: @escaping @Sendable () async -> Void) {
        startup.resume = action
    }

    /// Fences runtime failures against explicit user controls.
    func startupControlRevision() -> UUID {
        startup.controlID
    }

    /// Marks recovery without withdrawing a still-valid protection measurement on every retry.
    func markStartupRecovering() {
        guard !uninstallFenced else { publish(); return }
        needsRecovery = true
        if !requiresStartupProtection {
            snapshot.protection = .unprotected
        }
        publish()
    }

    /// Withdraws persisted tunnel passes only when there is existing protection to restore.
    func prepareStartupBlocking() async throws {
        guard !uninstallFenced else { return } // No pf, routes or DNS at startup during or after an uninstall (M05-T07).
        try requireStartupAdmission()
        if try await reconcileCutoverAtStartup() {
            return
        }
        try requireStartupAdmission()
        let controlID = startup.controlID
        await drainLifecycle()
        guard startup.controlID == controlID else { throw CancellationError() }
        try journal.mutate(generation: nil) { $0.cleanShutdownAt = nil }
        needsRecovery = true
        startup.failurePublishedFor = nil
        let task = Task { [self] in try await ensureStartupProtection() }
        operation = task
        let slot = operationID
        defer {
            if startup.controlID == controlID, operationID == slot {
                operation = nil
            }
        }
        do { try await boundedResult(task) }
        catch { throw startup.expiredControlID == controlID ? interruption(of: controlID) : error }
    }

    /// Publishes classified startup failure through the same serial slot as stop and settings.
    func recoveryFailed(_ reason: RecoveryFailureReason, expectedControlID: UUID? = nil) async throws {
        let controlID = expectedControlID ?? startup.controlID
        if expectedControlID != nil, startup.failurePublishedFor == controlID {
            return
        }
        guard startup.controlID == controlID else { throw CancellationError() }
        await drainLifecycle()
        guard startup.controlID == controlID, expectedControlID == nil || needsRecovery else { throw CancellationError() }
        needsRecovery = true
        let task = Task { [self] in
            try await publishRecoveryFailure(reason, controlID: controlID)
            startup.failurePublishedFor = controlID
        }
        operation = task
        let slot = operationID
        defer {
            if startup.controlID == controlID, operationID == slot {
                operation = nil
            }
        }
        try await boundedResult(task)
    }

    /// Completed reconciliation with missing secrets is ready for app-assisted reconnect, not another startup retry.
    func shouldRetryStartup() -> Bool {
        !uninstallFenced && (needsRecovery || startup.reconciliationPending)
    }

    /// Refreshes startup input without running normal active-tunnel maintenance.
    func updateStartupUnderlay(_ event: UnderlayEvent) {
        underlay = event.snapshot; underlayMTU = event.mtu
    }

    /// Keeps blocking liveness checks at five seconds; successful startup-policy verification renews its evidence time.
    func verifyRecoveryProtection() async throws {
        guard needsRecovery, requiresStartupProtection, operation == nil, !uninstallFenced else { return }
        let controlID = startup.controlID, epoch = generation
        let task = Task { [self] in
            try check(epoch)
            try await ensureStartupProtection()
            try check(epoch)
            publish()
        }
        operation = task
        let slot = operationID
        defer {
            if startup.controlID == controlID, operationID == slot {
                operation = nil
            }
        }
        try await boundedResult(task)
    }

    /// SIGTERM preserves persistent intent and its token. No orderly marker is written before policy completion.
    func shutdownCleanly() async throws {
        startup.controlID = UUID()
        acceptingRequests = false
        operation?.cancel(); cancelBackgroundWork()
        if let operation {
            _ = await operation.result
        }
        operation = nil
        let keep = intended != nil || settings.lockdown
        let current = await ports.policy.current()
        if keep || requiresStartupProtection || current != .disconnected {
            try await applyPolicy(keep ? .error : .disconnected, generation: generation, recovery: true)
        }
        if keep {
            try await acquireToken(generation)
        } else if let token = journal.snapshot().pfToken {
            try await ports.policy.releaseToken(token)
            try journal.mutate(generation: nil) { $0.pfToken = nil; $0.pfBootSession = nil }
        }
        try journal.mutate(generation: nil) { $0.cleanShutdownAt = clock.wallNow }
    }
}

package extension TunnelController {
    internal func stopDuringRecovery(
        profileID: UUID, uid: UInt32, retainingSecrets: Bool = false, admission: borrowing Admission,
    ) async throws -> Generation {
        guard intended == nil || intended?.profileID == profileID else { throw DaemonFailure.controllerAnotherTunnelActive }
        let owner: UInt32
        if let intended {
            owner = intended.ownerUID
        } else {
            guard let found = try await registry.ownerUID(for: profileID) else { throw DaemonFailure.registryNotFound }
            owner = found
        }
        guard uid == 0 || uid == owner else { throw DaemonFailure.registryNotOwner }
        startup.controlID = UUID()
        let epoch = try reserve(intent: nil, deletingSecretsOf: retainingSecrets ? nil : profileID, by: admission)
        stoppingProfile = (profileID, epoch)
        stopsInFlight += 1
        defer {
            stopsInFlight -= 1
            if stoppingProfile?.generation == epoch {
                stoppingProfile = nil
            }
        }
        startup.bootSelectionSuppressed = true
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let task = Task { [self] in
            if let previous {
                _ = await previous.result
            }
            try check(epoch)
            try await finishRecoveryStop(profileID: profileID, epoch: epoch, deletesSecrets: !retainingSecrets)
        }
        operation = task
        try await awaitOperation(task, generation: epoch)
        requestStartupRetry()
        return epoch
    }

    private func finishRecoveryStop(profileID: UUID, epoch: Generation, deletesSecrets: Bool) async throws {
        var failed = false
        transition(.stopping(epoch, reason: .userRequested), protection: .unknown)
        do {
            try withdrawCaptiveException()
            try await applyPolicy(settings.lockdown ? .lockdown : .disconnecting, generation: epoch)
        } catch { failed = true }
        // Persisted resources are removed only after identity-aware inspection.
        for resource in journal.snapshot().resources {
            do {
                try await removeOwnedResources(resource) { try check(epoch) }
                try journal.mutate(generation: epoch) { $0.resources.removeAll { $0.generation == resource.generation } }
            } catch { failed = true }
        }
        try await performStop(profileID: profileID, reason: .userRequested, explicit: deletesSecrets, generation: epoch)
        if failed {
            pendingTeardownProfileID = profileID
            snapshot.recoveryFailureReason = .reconciliationFailed
            transition(.failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false), protection: .unknown)
            throw DaemonFailure.controllerOperationFailed
        }
    }

    func setRecoverySettings(_ requested: MacGlobalSettings, uid: UInt32?) async throws {
        guard AuthorisationTable.recoveryAllows(from: settings, to: requested),
              (1 ... 3600).contains(requested.captiveWindowSeconds) else { throw DaemonError.recovering }
        try requireNoUninstall()
        startup.controlID = UUID()
        let epoch = try reserve(intent: intended)
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let task = Task { [self] in
            if let previous {
                _ = await previous.result
            }
            try check(epoch)
            try await finishRecoverySettings(requested, uid: uid)
        }
        operation = task
        try await awaitOperation(task, generation: epoch)
        requestStartupRetry()
    }

    private func finishRecoverySettings(_ requested: MacGlobalSettings, uid: UInt32?) async throws {
        try requireNoUninstall()
        settings = requested
        try journal.mutate(generation: generation) {
            $0.settings = requested
            if $0.protectionOwnerUID == nil {
                $0.protectionOwnerUID = uid
            }
        }
        try await ensureStartupProtection()
        clearPolicyFailure()
        snapshot.protection = requiresStartupProtection ? .blocked : .unprotected; publish()
    }

    func classifyStartupFailure(_ error: any Error) -> RecoveryFailureReason {
        if let failure = error as? DaemonFailure, let reason = failure.recoveryReason {
            return reason
        }
        // Stage 2's own secure-install read (`requireSecureInstall`) has already published this reason and the policy; the
        // failure it throws keeps the label instead of overwriting it with the generic start failure (M1-31).
        if let wire = error as? DaemonError, wire == .secureInstallRequired {
            return .secureInstallRequired
        }
        if journal.snapshot().entries.last?.step == .resolve {
            return .resolverUnavailable
        }
        return intended == nil ? .reconciliationFailed : .intentStartFailed
    }
}

package extension TunnelController {
    func repairRegistration(_ action: @escaping @Sendable (isolated TunnelController) async throws -> Void) async throws {
        startup.controlID = UUID()
        let epoch = try reserve(intent: intended)
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let task = Task { [self] in
            if let previous {
                _ = await previous.result
            }
            try check(epoch)
            try await action(self)
            try check(epoch)
        }
        operation = task
        try await awaitOperation(task, generation: epoch)
        requestStartupRetry()
    }

    var requiresStartupProtection: Bool {
        let value = journal.snapshot()
        return intended != nil || value.intent != nil || settings.lockdown || value.settings.lockdown
            || value.pfPolicy != .disconnected || value.pfToken != nil || value.pfEnableAttempted != nil
    }

    func ensureStartupProtection() async throws {
        guard requiresStartupProtection else { return }
        let epoch = generation
        try check(epoch)
        let current = await ports.policy.current()
        let verified = await ports.policy.verification()
        if current == .error || current == .lockdown, verified == .blocked {
            try await verifyPolicy()
        } else {
            try await applyPolicy(.error, generation: epoch, recovery: true)
        }
        try await acquireToken(epoch)
        if await ports.policy.verification() == .unknown {
            try await ports.policy.verifyEvaluation()
        }
        guard await ports.policy.verification() == .blocked else { throw DaemonFailure.pfVerification }
        try check(epoch)
        recordPolicyVerification()
        clearPolicyFailure()
        if snapshot.protection != .blocked {
            snapshot.protection = .blocked; publish()
        }
    }

    func publishRecoveryFailure(_ reason: RecoveryFailureReason, controlID: UUID) async throws {
        let before = snapshot
        let missing = if case .failed(_, _, true) = snapshot.phase {
            true
        } else {
            false
        }
        var cause = reason
        var protection: ProtectionState = .unprotected
        if requiresStartupProtection {
            do { try await ensureStartupProtection(); protection = .blocked }
            catch {
                guard controlID == startup.controlID, !(error is CancellationError) else { throw CancellationError() }
                cause = .blockingPolicyFailed; protection = .unknown
            }
        }
        guard controlID == startup.controlID else { throw CancellationError() }
        snapshot.recoveryFailureReason = cause
        let phase = TunnelPhase.failed(
            missing ? .secretsUnavailable : .backendUnavailable,
            blockedByPolicy: protection == .blocked,
            needsSecrets: missing,
        )
        if snapshot.phase != phase || snapshot.protection != protection {
            transition(phase, protection: protection)
        } else if snapshot != before {
            publish()
        }
    }
}

package extension TunnelController {
    func requireSecureInstall() async throws {
        let verified = await secureInstall.status().state == .verified
        if verified {
            startup.installWasVerified = true
            if startup.secureInstallRegressed {
                // Healed: the failure policy a regression requested but stage 2's slot kept from running is stale (M1-33 N1).
                startup.secureInstallRegressed = false; maintenanceState.securePolicyPending = false
                maintenanceState.retryAt = clock.now
            }
            return
        }
        if !startup.secureInstallRegressed, startup.installWasVerified || intended != nil || settings.lockdown {
            startup.secureInstallRegressed = true; maintenanceState.securePolicyPending = true
            snapshot.protection = .unknown; snapshot.recoveryFailureReason = .secureInstallRequired; publish()
        }
        try await enforcePendingSecurePolicy()
        throw DaemonError.secureInstallRequired
    }

    /// A flag edge requests one serial blocking operation, including when detected inside another operation. The request
    /// holds only while the regression it was raised for does: `secureInstallRegressed` is the single source of truth, so a
    /// request that outlived a heal is dropped here rather than applied to a healthy tunnel (M1-33 N1; ADR-009: a regression
    /// that is still present still applies the failure policy).
    func enforcePendingSecurePolicy() async throws {
        guard maintenanceState.securePolicyPending, !uninstallFenced else { return }
        guard startup.secureInstallRegressed else { maintenanceState.securePolicyPending = false; return }
        guard operation == nil else { return }
        maintenanceState.securePolicyPending = false
        let epoch = generation
        let task = Task { [self] in
            try withdrawCaptiveException()
            try await applyPolicy(failurePolicy, generation: epoch)
            try check(epoch)
            snapshot.protection = .unknown; snapshot.recoveryFailureReason = .secureInstallRequired; publish()
        }
        operation = task
        try await awaitOperation(task, generation: epoch)
    }
}
