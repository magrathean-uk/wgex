// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

/// Startup reconciliation proper (stage 1 of `reconcileAtStartup`). Every await that can outlive its stage is followed by
/// `requireStartupStage`: a stage whose watchdog expired, or that a control superseded, resumes into a newer world and
/// must reserve nothing, apply nothing and hand nothing over.
extension TunnelController {
    package func commitReconciliation() {
        needsRecovery = false; startup.reconciliationPending = false
        if journal.snapshot().resources.isEmpty, journal.snapshot().pendingSecretDeletions.isEmpty {
            pendingTeardownProfileID = nil
        }
        startup.tickRetryAt = nil; startup.tickRetryAttempt = 0
        snapshot.recoveryFailureReason = nil; publish()
        scheduleOnDemand(onDemand.startupEvaluated ? .recoveryEnded : .daemonStart)
        onDemand.startupEvaluated = true
        scheduleReleaseReplay()
    }

    internal func performReconciliation(controlID: UUID, admission: borrowing Admission) async throws {
        let persisted = journal.snapshot()
        intended = persisted.intent; settings = persisted.settings
        // RT-22 applies only when there is persisted protection to restore.
        try await ensureStartupProtection()
        let registeredBoot: TunnelIntent?
        do { registeredBoot = try await registry.bootIntent() }
        catch DaemonFailure.registryMultipleBootProfiles { throw DaemonFailure.startup(.multipleBootProfiles) }
        catch { throw DaemonFailure.startup(.profileUnavailable) }
        // ADR-030 section 7: an armed boot profile gets no boot reservation; the on-demand coordinator decides. Only a current
        // stage publishes what it read, and only if no newer commit was published meanwhile (a disarm during recovery).
        // A record that cannot be read is reported through recovery status, never taken as nothing armed; a disarm replaces it.
        let selection: ArmedSelection
        do { selection = try await registry.armedSelection() }
        catch { throw DaemonFailure.startup(.profileUnavailable) }
        await pauseOnDemand(.recoveryRead)
        try requireStartupStage(controlID)
        applyArmedSelection(selection)
        let boot = registeredBoot.flatMap { $0.profileID == onDemandArmedProfileID ? nil : $0 }
        // The verdict is read, then the stage's identity is checked, and only a current stage may record it: a stale one
        // must not flag a recovered tunnel for another reconciliation (M1-29 R2).
        let installVerified = await secureInstall.status().state == .verified
        try requireStartupStage(controlID)
        guard installVerified else {
            startup.reconciliationPending = true
            throw DaemonFailure.startup(.secureInstallRequired)
        }
        if intended == nil, !startup.bootSelectionSuppressed, let boot {
            // A boot reservation is a newer claim: the release its profile was owed goes first (ADR-030 section 6). The reads
            // above may have outlived this stage (expiry, a control): only the current stage reserves.
            do { try await registry.claimOnDemand(boot.profileID, admission: admission) }
            catch { throw DaemonFailure.startup(.profileUnavailable) }
            try requireStartupStage(controlID)
            _ = try reserve(intent: boot, by: admission)
            try await ensureStartupProtection()
        }
        if intended != nil || settings.lockdown, underlay.v4 == nil, underlay.v6 == nil {
            throw DaemonFailure.startup(.noPrimaryInterface)
        }
        try await reconcileStartupResources(persisted, controlID: controlID, admission: admission)
        try requireStartupStage(controlID)
        noteStepBegin(.applyIntents)
        try entry(.applyIntents, .willApply, generation: generation)
        try await restoreStartupIntent(persisted, boot: boot, controlID: controlID, admission: admission)
        // A reserved boot start completes this entry itself, once it has ended.
        if startup.bootStart == nil {
            try entry(.applyIntents, .didApply, generation: generation)
        }
    }

    private func reconcileStartupResources(
        _ persisted: DaemonJournalDocument, controlID: UUID, admission: borrowing Admission,
    ) async throws {
        try requireStartupStage(controlID)
        cancelBackgroundWork()
        // Only the handles shut down here leave the map, and they leave it before the stage's identity is checked: a stale
        // stage must not keep them listed, and must not drop an engine a newer stage has stored since (M1-29 R6).
        let shutDown = engines
        for engine in shutDown.values {
            await engine.shutdown()
        }
        for generation in shutDown.keys {
            engines.removeValue(forKey: generation)
        }
        try requireStartupStage(controlID)
        noteStepBegin(.inspectReality)
        try entry(.inspectReality, .willApply, generation: generation)
        for resource in persisted.resources {
            try await removeOwnedResources(resource) { try requireStartupStage(controlID) }
        }
        try journal.mutate(generation: generation) { $0.resources = [] }
        try entry(.inspectReality, .didApply, generation: generation)
        try await reconcileCaptiveWindow(persisted, controlID: controlID)
        for profileID in persisted.pendingSecretDeletions {
            // A claim made after the deletion was journalled (armed, start-before-login, an intent) keeps the bundle, whichever
            // of its writes a crash lost: retention is read from current state here, never from the journalled snapshot.
            try await secretWrite(profileID) { controller in
                let retained = await controller.secretsRetained(profileID)
                try controller.requireStartupStage(controlID)
                if !retained {
                    try await controller.secrets.deleteBundle(profileID: profileID)
                }
            }
            try requireStartupStage(controlID)
            try journal.mutate(generation: generation) { $0.pendingSecretDeletions.remove(profileID) }
        }
        try await registry.reconcilePurges(admission: admission)
        try requireStartupStage(controlID)
        try await sweepUnclaimedBundles(controlID: controlID)
    }

    private func restoreStartupIntent(
        _ persisted: DaemonJournalDocument, boot: TunnelIntent?, controlID: UUID, admission: borrowing Admission,
    ) async throws {
        if settings.lockdown {
            try await acquireToken(generation)
            try requireStartupStage(controlID)
            try await applyPolicy(.lockdown, generation: generation, recovery: true)
            try requireStartupStage(controlID)
        }
        if intended == nil, !startup.bootSelectionSuppressed {
            intended = boot
        }
        let disconnectedLogout = persisted.pfPolicy == .disconnected && persisted.pfToken == nil
        let lockdownLogout = settings.lockdown && persisted.pfPolicy == .lockdown
        let suspended = persisted.loginSuspended == true && persisted.resources.isEmpty && (disconnectedLogout || lockdownLogout)
        if let intent = intended, !suspended {
            try journal.mutate(generation: generation) { $0.loginSuspended = false }
            let registration: DaemonProfile
            do { registration = try await registry.profile(intent.profileID, connectionUID: intent.ownerUID) }
            catch { throw DaemonFailure.startup(.profileUnavailable) }
            // A stale stage must not reserve a generation or leave a start behind: the reserve is the last statement of a
            // current stage's turn. The start is its own bounded operation after reconciliation (reconcileAtStartup).
            // The checks before this await catch every earlier loss of identity. During `registry.profile` itself a stage loses
            // it only through cancellation (every control and the expiry cancel the stage): a waiter queued on the registry's
            // slot is then refused, and one already admitted resumes with the answer, a window one actor hop wide that no
            // fake can hold a task inside deterministically (mutant M10b of M1-25 fix pass 1 survives for that reason).
            try requireStartupStage(controlID)
            startup.bootStart = try PendingBootStart(
                registration: registration, generation: reserve(intent: intent, by: admission), controlID: controlID,
            )
        } else {
            if suspended {
                intended = nil
            }
            // The policy is read first, and everything it informs is decided after the read: a stage that was parked here
            // while a control changed the settings must neither act on the old `final` nor act at all.
            let current = await ports.policy.current()
            try requireStartupStage(controlID)
            let final: PacketFilterPolicy = settings.lockdown ? .lockdown : .disconnected
            if requiresStartupProtection || current != final {
                try await applyPolicy(final, generation: generation, recovery: true)
                try requireStartupStage(controlID)
            }
            if final == .disconnected, let token = journal.snapshot().pfToken {
                try await ports.policy.releaseToken(token)
                try requireStartupStage(controlID)
                try journal.mutate(generation: generation) { $0.pfToken = nil }
            }
            transition(.idle, protection: settings.lockdown ? .blocked : .unprotected)
        }
    }

    private func reconcileCaptiveWindow(_ persisted: DaemonJournalDocument, controlID: UUID) async throws {
        guard persisted.captiveWindow != nil else { return }
        // Continuous deadlines cannot be trusted across process/boot epochs. Close even if wall time moved backwards.
        noteStepBegin(.closeCaptive)
        try entry(.closeCaptive, .willApply, generation: generation)
        try await applyPolicy(.error, generation: generation, recovery: true)
        try requireStartupStage(controlID)
        try journal.mutate(generation: generation) { $0.captiveWindow = nil }
        try entry(.closeCaptive, .didApply, generation: generation)
    }
}
