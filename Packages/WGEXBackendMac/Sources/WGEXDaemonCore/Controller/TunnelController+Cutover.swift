// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public extension TunnelController {
    /// Arms rollback durably before invoking the ordinary start path. System sleep pauses the deadline.
    @discardableResult
    func startCutover(
        profileID: UUID, connectionUID: UInt32, confirmWithin seconds: Int,
        secrets bundle: consuming SecretBundle? = nil, expectedGeneration: Generation? = nil, appSecrets: AppSecretsHandoff? = nil,
    ) async throws -> Generation {
        guard (60 ... 3600).contains(seconds) else { throw DaemonError.malformedMessage }
        let supplied = try Self.pendingSecrets(consume bundle)
        // One admission from receipt to reservation: the trial arming and the start both commit under it, so a stop of the
        // profile received during the checks below, or during the app's secrets handoff, supersedes the whole cutover.
        return try await withCommand(.cutover, profile: profileID, input: false) { admission in
            try await withAppSecrets(profileID, payload: supplied, handoff: appSecrets, admission: admission) { admission, payload in
                try await armCutover(
                    profileID: profileID, connectionUID: connectionUID, confirmWithin: seconds, payload: payload,
                    expectedGeneration: expectedGeneration, admission: admission,
                )
            }
        }
    }
}

private extension TunnelController {
    func armCutover(
        profileID: UUID, connectionUID: UInt32, confirmWithin seconds: Int, payload: PendingDaemonSecrets?,
        expectedGeneration: Generation?, admission: borrowing Admission,
    ) async throws -> Generation {
        try await requireSecureInstall()
        let record = try await registry.registrationForStart(profileID, connectionUID: connectionUID)
        try checkExpected(expectedGeneration)
        guard acceptingRequests, operation == nil, !needsRecovery, intended == nil, !settings.lockdown,
              !cutoverIsArmed, journal.snapshot().cutover?.rollbackPending != true else { throw DaemonFailure(code: .slotRefused) }
        // Missing secrets are requested from the running app before any trial effects are armed.
        if payload == nil {
            do { _ = try await secrets.loadBundle(profileID: profileID) }
            catch { throw DaemonError.secretsUnavailable }
        }
        guard try await registry.bootIntent() == nil,
              acceptingRequests, operation == nil, !needsRecovery, intended == nil, !settings.lockdown,
              !cutoverIsArmed, journal.snapshot().cutover?.rollbackPending != true else { throw DaemonFailure(code: .slotRefused) }
        try requireCurrentStart(admission, profileID: profileID, restarting: nil)
        let trial = CutoverRecord(
            profileID: profileID, ownerUID: record.ownerUID,
            deadline: clock.wallNow.addingTimeInterval(TimeInterval(seconds)),
            awakeDeadline: operationClock.now + .seconds(seconds),
            launchID: cutover.launchID,
        )
        try journal.mutate(generation: generation) { $0.cutover = trial; $0.protectionOwnerUID = record.ownerUID }
        refreshCutoverStatus()
        // A weak task has no controller retain cycle; the durable id makes confirmed/replaced timers inert.
        Task { [weak self, operationClock] in
            do {
                try await operationClock.sleep(for: max(.zero, trial.awakeDeadline - operationClock.now))
                try await self?.expireCutover(trial.id)
            } catch { /* The journal retains incomplete rollback for startup or an explicit abort retry. */ }
        }
        do {
            return try await start(
                profileID: profileID, connectionUID: connectionUID, payload: payload, transport: nil,
                expectedGeneration: expectedGeneration, origin: .manual, admission: admission,
            )
        } catch {
            if journal.snapshot().cutover?.id == trial.id, cutoverIsArmed {
                try? await rollbackCutover(reason: .startFailed)
            }
            throw error
        }
    }
}

public extension TunnelController {
    /// Commits only a completed active trial strictly before its awake-time deadline.
    func confirmCutover(connectionUID: UInt32) async throws {
        guard let trial = journal.snapshot().cutover else { throw DaemonFailure(code: .slotRefused) }
        try authoriseCutover(trial, uid: connectionUID)
        if trial.state == .rolledBack(reason: .timeout) {
            throw DaemonError.tunnel(.timedOut)
        }
        if trial.state == .confirmed {
            return
        }
        guard cutoverIsArmed, operation == nil, case .active = snapshot.phase else { throw DaemonFailure(code: .slotRefused) }
        guard operationClock.now < trial.awakeDeadline else {
            try await rollbackCutover(reason: .timeout)
            throw DaemonError.tunnel(.timedOut)
        }
        try journal.mutate(generation: generation) {
            $0.cutover?.state = .confirmed
            $0.cutover?.awakeDeadlineSeconds = 0; $0.cutover?.awakeDeadlineAttoseconds = 0
        }
        refreshCutoverStatus(); publish()
    }

    /// Reverts an armed or confirmed trial. Retrying an incomplete rollback attempts every step again.
    func abortCutover(connectionUID: UInt32) async throws {
        guard let trial = journal.snapshot().cutover else { return }
        try authoriseCutover(trial, uid: connectionUID)
        if case .rolledBack = trial.state, !trial.rollbackPending {
            return
        }
        try await rollbackCutover(reason: .aborted)
    }
}

package extension TunnelController {
    /// CAS installation bypasses handle, so it must enforce the pending-rollback admission barrier itself.
    func requireCutoverRegistryAdmission() throws {
        guard journal.snapshot().cutover?.rollbackPending != true else { throw DaemonFailure.registryBusy }
    }

    var cutoverNeedsRollback: Bool {
        cutoverIsArmed || journal.snapshot().cutover?.rollbackPending == true
    }

    /// Uninstall (M05-T07): ends an armed trial, or retries a pending rollback, in the uninstall's own order. The trial's
    /// intent, network resources and engines go as in the ordinary rollback; its boot flag and bundle and the pf policy and
    /// reference are left to the uninstall's later steps, which release the kill switch before any storage step. Throws while
    /// the teardown is incomplete, and a retry attempts it again.
    func rollbackCutoverForUninstall() async throws {
        guard cutoverNeedsRollback else { return }
        try await rollbackCutover(reason: .aborted, forUninstall: true)
    }

    /// Refused serial admission returns normally inside maintenance, then reports busy outside its failure-policy handler.
    func cutoverAdmittedMaintenance(
        _ body: @escaping @Sendable (isolated TunnelController, Generation) async throws -> Bool,
    ) async throws {
        let admitted = Mutex(false)
        try await maintenance { controller, epoch in
            let accepted = try await body(controller, epoch)
            admitted.withLock { $0 = accepted }
        }
        guard admitted.withLock({ $0 }) else { throw DaemonFailure(code: .slotRefused) }
    }

    var cutoverIsArmed: Bool {
        if case .armed = journal.snapshot().cutover?.state {
            return true
        }
        return false
    }

    func refreshCutoverStatus() {
        if cutoverIsArmed || journal.snapshot().cutover?.rollbackPending == true {
            revokeCommitAdmissions(DaemonFailure(code: .slotRefused))
        }
        snapshot.cutover = journal.snapshot().cutover?.state
        snapshot.cutoverRollbackFailures = journal.snapshot().cutover?.failures ?? []
    }

    /// Called before either startup blocking or normal reconciliation; reboot never restores trial intent.
    func reconcileCutoverAtStartup() async throws -> Bool {
        guard let trial = journal.snapshot().cutover else { return false }
        refreshCutoverStatus()
        guard trial.rollbackPending || (cutoverIsArmed && trial.launchID != cutover.launchID) else { return false }
        let reason: CutoverRollbackReason = if case let .rolledBack(previous) = trial.state {
            previous
        } else {
            .daemonRestart
        }
        do { try await rollbackCutover(reason: reason) }
        catch {
            // Pending cutover cleanup has its own retry/abort path and already published its measured failure.
            guard cutoverRollbackIsRecorded(trial.id) else { throw error }
        }
        guard cutoverRollbackIsRecorded(trial.id) else { throw DaemonError.protectionUnknown(reason: "cutoverRollbackIncomplete") }
        return true
    }

    private func cutoverRollbackIsRecorded(_ id: UUID) -> Bool {
        guard let trial = journal.snapshot().cutover, trial.id == id else { return false }
        if case .rolledBack = trial.state {
            return true
        }
        return trial.rollbackPending
    }

    func expireCutover(_ id: UUID) async throws {
        // Under the uninstall fence the trial is the uninstall's to roll back, in its own order.
        guard !uninstallFenced, let trial = journal.snapshot().cutover, trial.id == id else { return }
        if trial.rollbackPending, let operation {
            _ = await operation.result
            try requireCutoverRollbackComplete()
            return
        }
        guard cutoverIsArmed,
              operationClock.now >= trial.awakeDeadline else { return }
        try await rollbackCutover(reason: .timeout)
    }

    private func authoriseCutover(_ trial: CutoverRecord, uid: UInt32) throws {
        guard uid == 0 || uid == trial.ownerUID else { throw DaemonError.notAuthorised(.notOwner) }
    }

    /// `forUninstall` leaves the trial's boot flag and bundle, and the pf policy and reference, to the uninstall's own steps.
    /// Any rollback under the uninstall fence (a cutover start the fence revoked, say) takes that order too.
    private func rollbackCutover(reason: CutoverRollbackReason, forUninstall: Bool = false) async throws {
        guard let trial = journal.snapshot().cutover else { return }
        let uninstallOrder = forUninstall || uninstallFenced
        if trial.rollbackPending, let operation {
            _ = await operation.result
            try requireCutoverRollbackComplete()
            return
        }
        // Suppress every automatic restart before draining the previous generation.
        startup.controlID = UUID(); startup.bootSelectionSuppressed = true
        settings.lockdown = false; intended = nil
        var failures = Array(trial.failures.suffix(32))
        let deletesSecrets: UUID? = uninstallOrder ? nil : trial.profileID
        do {
            try journal.mutate(generation: nil) {
                $0.cutover?.state = .rolledBack(reason: reason); $0.cutover?.rollbackPending = true
                $0.intent = nil; $0.settings.lockdown = false; $0.captiveWindow = nil
                if let deletesSecrets {
                    $0.pendingSecretDeletions.insert(deletesSecrets)
                }
            }
        } catch { failures.append("cutoverIntent") }
        do { _ = try reserve(intent: nil, deletingSecretsOf: deletesSecrets) }
        catch { failures.append("generation") }
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let initialFailures = failures
        let task = Task<Void, any Error> { [self] in
            if let previous {
                _ = try? await boundedResult(previous)
            }
            await performCutoverRollback(trial, reason: reason, initialFailures: initialFailures, forUninstall: uninstallOrder)
        }
        operation = task
        let slot = operationID
        // Each production adapter already has a deadline. The ordinary watchdog's blocking fallback is inappropriate here.
        try await task.value
        if operationID == slot {
            operation = nil
        }
        try requireCutoverRollbackComplete()
    }

    private func requireCutoverRollbackComplete() throws {
        guard let trial = journal.snapshot().cutover, case .rolledBack = trial.state, !trial.rollbackPending else {
            throw DaemonError.protectionUnknown(reason: "cutoverRollbackIncomplete")
        }
    }

    /// The uninstall's rollback (`forUninstall`) runs only the intent, network and engine steps: the uninstall releases the
    /// kill switch (empty policy, then the reference) in its own later steps, before any storage step removes the boot flag
    /// and the bundle, so nothing here may write storage or skip past a failed release.
    private func performCutoverRollback(
        _ trial: CutoverRecord, reason: CutoverRollbackReason, initialFailures: [String], forUninstall: Bool,
    ) async {
        var failures = initialFailures
        var incomplete = false
        snapshot.phase = .stopping(generation, reason: .userRequested); snapshot.protection = .unknown
        refreshCutoverStatus(); publish()
        incomplete = await cutoverStep(.cutoverIntent, failures: &failures) {
            try self.journal.mutate(generation: nil) {
                $0.intent = nil; $0.loginSuspended = false; $0.settings.lockdown = false; $0.captiveWindow = nil
            }
        } || incomplete
        if !forUninstall {
            incomplete = await cutoverStep(.cutoverBootIntent, failures: &failures) {
                do { try await self.registry.setStartBeforeLogin(trial.profileID, enabled: false, connectionUID: trial.ownerUID) }
                catch DaemonFailure.registryNotFound { /* An absent registration has no boot intent left to disable. */ }
            } || incomplete
        }
        incomplete = await rollbackCutoverResources(failures: &failures) || incomplete
        if !forUninstall {
            incomplete = await releaseCutoverPolicy(trial, failures: &failures) || incomplete
        }
        await finishCutoverRollback(reason: reason, failures: failures, incomplete: incomplete)
    }

    /// The ordinary rollback's tail: the empty policy, the reference release and the trial bundle's deletion.
    private func releaseCutoverPolicy(_ trial: CutoverRecord, failures: inout [String]) async -> Bool {
        var incomplete = await cutoverStep(.finalPolicy, failures: &failures) {
            // Journal failures must not prevent the empty anchor from being loaded.
            try await self.ports.policy.apply(.disconnected)
            guard await self.ports.policy.verification() == .unprotected else { throw DaemonFailure.pfVerification }
            try self.journal.mutate(generation: nil) { $0.pfPolicy = .disconnected }
        }
        incomplete = await cutoverStep(.releaseToken, failures: &failures) {
            if await self.ports.policy.verification() != .unprotected {
                try await self.ports.policy.apply(.disconnected)
            }
            if let token = self.journal.snapshot().pfToken {
                try await self.ports.policy.releaseToken(token)
            }
            guard await self.ports.policy.verification() == .unprotected else { throw DaemonFailure.pfVerification }
            try self.journal
                .mutate(generation: nil) { $0.pfToken = nil; $0.pfBootSession = nil; $0.pfTokenPID = nil; $0.pfEnableAttempted = nil }
        } || incomplete
        incomplete = await cutoverStep(.deleteSecrets, failures: &failures) {
            try await self.secrets.deleteBundle(profileID: trial.profileID)
            try self.journal.mutate(generation: nil) { $0.pendingSecretDeletions.remove(trial.profileID) }
        } || incomplete
        return incomplete
    }

    private func rollbackCutoverResources(failures: inout [String]) async -> Bool {
        var incomplete = false
        for resource in journal.snapshot().resources {
            incomplete = await cutoverStep(.removeDNS, failures: &failures) {
                try await self.ports.dns.remove(generation: resource.generation)
            } || incomplete
            incomplete = await cutoverStep(.removeRoutes, failures: &failures) {
                try await self.ports.routes.removeRoutes(of: resource.generation)
            } || incomplete
            incomplete = await cutoverStep(.inspectReality, failures: &failures) {
                let observed = try await self.ports.reality.inspect(resource)
                try await self.ports.reality.removeOwned(DaemonReconciliation.ownedResources(resource, observed: observed))
            } || incomplete
            if let identity = resource.identity {
                incomplete = await cutoverStep(.configureInterface, failures: &failures) {
                    try await self.ports.device.removeAddresses(identity, generation: resource.generation)
                } || incomplete
            }
        }
        let retired = engines; engines = [:]
        for engine in retired.values {
            incomplete = await cutoverStep(.engineDown, failures: &failures) {
                do { try await engine.down() } catch EngineError.deviceClosed { /* Already down. */ }
            } || incomplete
            _ = await cutoverStep(.engineShutdown, failures: &failures) { await engine.shutdown() }
        }
        return incomplete
    }

    private func finishCutoverRollback(reason: CutoverRollbackReason, failures: [String], incomplete: Bool) async {
        var failures = failures
        var incomplete = incomplete
        let pending = incomplete
        let recordedFailures = failures
        incomplete = await cutoverStep(.cutoverComplete, failures: &failures) {
            try self.journal.mutate(generation: nil) {
                $0.cutover?.state = .rolledBack(reason: reason); $0.cutover?.rollbackPending = pending
                $0.cutover?.awakeDeadlineSeconds = 0; $0.cutover?.awakeDeadlineAttoseconds = 0
                $0.cutover?.failures = recordedFailures
                if !pending {
                    $0.resources = []
                }
            }
        } || incomplete
        rotation.candidates = [:]; rotation.hosts = [:]; rotation.indices = [:]; rotation.handshakePeers = []; rotation.attemptStarted = nil
        maintenanceState.retryAt = nil; startup.tickRetryAt = nil; maintenanceState.securePolicyPending = false; maintenanceState
            .stableActiveSince = nil
        // Ordinary startup recovery deliberately blocks. A pending trial rollback must remain on its own abort path.
        needsRecovery = false; startup.reconciliationPending = false
        pendingTeardownProfileID = incomplete ? journal.snapshot().cutover?.profileID : nil
        protectionFailureReason = nil
        snapshot.cutover = .rolledBack(reason: reason); snapshot.cutoverRollbackFailures = failures
        snapshot.phase = incomplete ? .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false) : .idle
        snapshot.recoveryFailureReason = incomplete ? .reconciliationFailed : nil
        snapshot.protection = await ports.policy.verification() == .unprotected ? .unprotected : .unknown
        publish()
    }

    /// Checkpoint and journal failures are recorded independently and never skip the effect. Each effect has one bounded retry.
    private func cutoverStep(_ step: DaemonStep, failures: inout [String], action: () async throws -> Void) async -> Bool {
        do { try await steps.before(step, generation: generation); try entry(step, .willApply, generation: generation, recovery: true) }
        catch { failures.append(step.rawValue + ":journal") }
        for attempt in 0 ... 1 {
            do {
                try await action()
                do { try entry(step, .didApply, generation: generation, recovery: true) }
                catch { failures.append(step.rawValue + ":journal") }
                return false
            } catch {
                failures.append(step.rawValue)
                if attempt == 1 {
                    return true
                }
            }
        }
        return true
    }
}
