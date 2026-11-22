// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy

/// ADR-030 control commands. Each is admitted before its first await (`withCommand`), commits through the registry by
/// compare-and-set under its admission and publishes only the registry's committed selection, never a value it read before
/// an await.
internal extension TunnelController {
    // MARK: - Committed state

    /// Publishes a committed armed selection. One older than the selection already held is ignored, so a continuation that
    /// read before a newer commit can never restore what that commit replaced.
    func applyArmedSelection(_ selection: ArmedSelection?) {
        guard let selection else { return }
        if let held = onDemand.armedVersion, selection.version < held {
            return
        }
        onDemand.armedVersion = selection.version
        let next = selection.record.flatMap(ArmedOnDemand.init)
        guard next != onDemand.armed else { return }
        if next?.profileID != onDemand.armed?.profileID {
            onDemand.cancelSettling(); onDemand.ask = nil
        }
        onDemand.armed = next
        onDemand.epoch &+= 1
        publishOnDemand()
    }

    /// Reads the committed selection and publishes it; used after every registry write, failed or not.
    func refreshArmedSelection() async {
        let selection = try? await registry.armedSelection()
        await pauseOnDemand(.selectionRead)
        applyArmedSelection(selection)
    }

    /// Loads the armed selection once; reconciliation does it first in production.
    func loadOnDemandArmed() async {
        guard !onDemand.loaded else { return }
        await refreshArmedSelection()
    }

    // MARK: - Requests

    /// `armOnDemand`: stores the secrets (armed is a retention reason), commits the selection against the registration it
    /// validated, and completes every release the record owes, the replaced profile's first among them. Evaluation follows
    /// even when a release fails; the release then stays owed for the next command or the next start. Nothing is held across
    /// the secure-install check or the secret write: a newer stop, manual command or arm supersedes the arm at its own
    /// admission, and the registry commits the arm only while no newer command committed the selection or the profile.
    /// Missing daemon-store secrets are requested from the app inside the same admission (`withAppSecrets`).
    func armOnDemand(_ id: UUID, uid: UInt32, bundle: consuming SecretBundle?, appSecrets: AppSecretsHandoff? = nil) async throws {
        let payload = try Self.pendingSecrets(consume bundle)
        defer { payload?.wipe() }
        try await withCommand(.arm, profile: id) { admission in
            try await withAppSecrets(id, payload: payload, handoff: appSecrets, admission: admission) { admission, payload in
                try await requireSecureInstall()
                try admission.requireLive()
                try requireArmAdmission()
                await loadOnDemandArmed()
                let record = try await registry.registrationForStart(id, connectionUID: uid)
                guard ArmedOnDemand(record) != nil else { throw DaemonFailure(code: .onDemandNotConfigured) }
                try await commitArm(record, uid: uid, payload: payload, admission: admission)
                defer { scheduleOnDemand(.armed) }
                try await completeReleases(for: admission)
            }
        }
    }

    /// The bundle publication, then the durable claim. A deletion decided between them treats the profile as retained
    /// (`publishing`), and the publication is one of the profile's ordered secret writes.
    private func commitArm(
        _ record: RegisteredProfile, uid: UInt32, payload: PendingDaemonSecrets?, admission: borrowing Admission,
    ) async throws {
        let id = record.registration.profile.id
        publishing[id, default: 0] += 1
        defer { endPublishing(id) }
        if let payload {
            _ = try Self.pack(SecretsWireLayout.decode(payload.copy()), profile: record.registration.profile)
            guard try await publishBundle(payload, for: record.registration) else { throw DaemonFailure.registryRevisionConflict }
        } else {
            _ = try await Self.pack(storedBundle(id), profile: record.registration.profile)
        }
        await pauseOnDemand(.armValidated(id))
        try requireArmAdmission()
        let commit: ArmCommit
        do { commit = try await registry.armOnDemand(id, connectionUID: uid, expected: record.registration, admission: admission) }
        catch {
            await refreshArmedSelection()
            throw error
        }
        // The retention is committed: a deletion journalled before it no longer applies (replay also skips armed profiles).
        try? journal.mutate(generation: nil) { $0.pendingSecretDeletions.remove(id) }
        applyArmedSelection(commit.selection)
    }

    func endPublishing(_ id: UUID) {
        publishing[id, default: 1] -= 1
        if publishing[id] == 0 {
            publishing.removeValue(forKey: id)
        }
    }

    func requireArmAdmission() throws {
        guard !cutoverIsArmed, journal.snapshot().cutover?.rollbackPending != true else { throw DaemonFailure(code: .slotRefused) }
        guard !needsRecovery, acceptingRequests else { throw DaemonFailure.controllerRecoveryRequired }
    }

    /// Publishes `payload` for `registration` only while that is still the profile's registration (same revision and key),
    /// as one of the profile's ordered secret writes, so a publication for a registration replaced meanwhile never
    /// overwrites what the newer one published and a deletion decided before it never lands after it. Returns whether it
    /// published.
    func publishBundle(_ payload: PendingDaemonSecrets, for registration: DaemonProfile) async throws -> Bool {
        let id = registration.profile.id
        return try await secretWrite(id) { controller in
            guard await controller.registry.isCurrentRegistration(registration) else { return false }
            await controller.pauseOnDemand(.publishing(id))
            let bundle = try SecretsWireLayout.decode(payload.copy())
            try await controller.secrets.saveBundle(bundle.wireBytes(), profileID: id)
            return true
        }
    }

    private func storedBundle(_ id: UUID) async throws -> SecretBundle {
        do { return try await SecretsWireLayout.decode(secrets.loadBundle(profileID: id)) }
        catch { throw DaemonFailure.controllerSecretsUnavailable }
    }

    /// `disarmOnDemand`: clears the selection and stops the profile if it is intended, whatever started it (section 6 rule
    /// 2). Start-before-login keeps the secrets of the profile it stops (ADR-030 section 7). During recovery it is also how
    /// an unreadable on-demand record is replaced, after which startup is retried. A stop kind: older starts, arms and
    /// on-demand actions of the profile are superseded at its admission, so it never waits for them.
    func disarmOnDemand(_ id: UUID, uid: UInt32) async throws {
        try await withCommand(.disarm, profile: id) { admission in
            guard let owner = try await registry.ownerUID(for: id) else { throw DaemonFailure.registryNotFound }
            guard owner == uid else { throw DaemonFailure.registryNotOwner }
            await loadOnDemandArmed()
            try await commitDisarm(id, stopsIntent: true, admission: admission)
            defer { publishOnDemand() }
            if needsRecovery || startup.reconciliationPending {
                requestStartupRetry()
            }
            let claim = intentClaims
            if try await !completeReleases(of: [id], for: admission), releasedIntent(id) != nil {
                do { try await releaseOnDemand(OnDemandRelease(profileID: id, stopsIntent: true), for: admission, boundClaim: claim) }
                catch is OnDemandReleaseDeferred { /* Unreachable for a disarm: kept for the shared release path. */ }
            }
        }
    }

    /// A manual connect disarms the armed profile and drops any release `id` was owed, in one durable write (rules 4 and
    /// 5), under the start's admission; a persistence failure fails the request with the profile still armed.
    func manualConnectOverridesOnDemand(_ id: UUID, admission: borrowing Admission) async throws {
        await refreshArmedSelection() // Read after the admission, never before it.
        let armed = onDemand.armed?.profileID
        do { try await applyArmedSelection(registry.manualConnectOnDemand(id, admission: admission)) }
        catch {
            await refreshArmedSelection()
            throw error
        }
        if let armed, armed != id {
            try await completeReleases(of: [armed], for: admission)
        }
    }

    /// A manual disconnect of the armed profile disarms it first, then the explicit stop follows under the same admission
    /// and is its release (rule 3). Failure handling as for a manual connect.
    func manualDisconnectOverridesOnDemand(_ id: UUID, admission: borrowing Admission) async throws {
        await loadOnDemandArmed()
        guard onDemand.armed?.profileID == id else { return }
        try await commitDisarm(id, stopsIntent: nil, admission: admission)
    }

    /// Clears the durable selection and publishes the committed one; after a failed write the cache follows the registry.
    private func commitDisarm(_ id: UUID, stopsIntent: Bool?, admission: borrowing Admission) async throws {
        await pauseOnDemand(.disarming(id))
        do { try await applyArmedSelection(registry.disarmOnDemand(id, stopsIntent: stopsIntent, admission: admission)) }
        catch {
            await refreshArmedSelection()
            throw error
        }
    }

    /// After an install or a boot-intent change: publishes the committed selection. An install that cleared the policy
    /// (`.off`, or no macOS rule) disarmed the profile first and recorded a retention-only release; the tunnel stays as it
    /// is (rule 7) and only the armed secret retention goes.
    func onDemandProfileChanged(_ id: UUID, admission: borrowing Admission) async {
        let before = onDemand.armed
        await refreshArmedSelection()
        let after = onDemand.armed
        if before?.profileID == id, after?.profileID != id {
            _ = try? await completeReleases(of: [id], for: admission)
            return
        }
        guard let before, let after, before.profileID == id, after.profileID == id, after != before else { return }
        let lists = { (armed: ArmedOnDemand) in armed.rules.map(\.ssidMatch) }
        scheduleOnDemand(.policyChanged(listChanged: after.requiresSSID && lists(after) != lists(before)))
    }

    /// Rule 8, under the removal's admission: disarms the profile before it goes, recording a retention-only release that
    /// the removal completes once the profile is gone (`completeReleases(of:)`).
    func onDemandProfileRemoving(_ id: UUID, admission: borrowing Admission) async throws {
        await loadOnDemandArmed()
        guard onDemand.armed?.profileID == id else { return }
        try await commitDisarm(id, stopsIntent: false, admission: admission)
        await pauseOnDemand(.cleanup(id))
    }

    // MARK: - Release and retention

    /// The intent a release stops: the live one, or during recovery the journalled one.
    private func releasedIntent(_ id: UUID) -> TunnelIntent? {
        if let intended, intended.profileID == id {
            return intended
        }
        guard needsRecovery, let journalled = journal.snapshot().intent, journalled.profileID == id else { return nil }
        return journalled
    }

    /// Completes the releases the durable record owes, all of them or those of `ids`, each removed once done; the record is
    /// read here, inside the caller's control `admission`, so a claim committed before it is never undone; every release stop
    /// carries that admission's receipt. Every release is attempted; the first failure is rethrown and leaves that release
    /// owed. Returns whether any was owed.
    @discardableResult
    func completeReleases(of ids: Set<UUID>? = nil, for admission: borrowing Admission) async throws -> Bool {
        // The claim is read before the record: a reservation that claims an intent after this read is newer than every
        // release read here, and a release stop bound to this claim stops nothing then.
        let claim = intentClaims
        let owed = try await registry.pendingReleases().filter { ids?.contains($0.profileID) ?? true }
        var failure: any Error?
        for release in owed {
            do {
                try await releaseOnDemand(release, for: admission, boundClaim: claim)
                try await registry.finishRelease(release, admission: admission)
            } catch is OnDemandReleaseDeferred { /* Still owed: the manual command holding the profile decides it. */ }
            catch {
                failure = failure ?? error
            }
        }
        if !owed.isEmpty {
            await refreshArmedSelection()
        }
        if let failure {
            throw failure
        }
        return !owed.isEmpty
    }

    /// Ends on-demand's claim on a profile. A release that stops the intent stops an intended profile as a user stop,
    /// keeping its secrets while start-before-login holds them (sections 6 and 7); any other drops the armed retention.
    /// The stop is bound to the intent claim its caller read before it read the release (`boundClaim`), so it never stops a
    /// connect claimed after that read, and it carries the receipt of the command it belongs to (`admission`), never one
    /// sampled after that command suspended (H9). A manual command in flight on the profile defers it.
    func releaseOnDemand(_ release: OnDemandRelease, for admission: borrowing Admission, boundClaim claim: UInt64) async throws {
        let id = release.profileID
        await pauseOnDemand(.releasing(id))
        guard release.stopsIntent, let intent = releasedIntent(id) else {
            await pauseOnDemand(.cleanup(id))
            await deleteSecretsUnlessRetained(id)
            return
        }
        let retains = await bootIntentRetains(id)
        await pauseOnDemand(.cleanup(id))
        // A manual command in flight on the profile decides a cleanup's or a replay's stop (ADR-030 section 6): the release
        // stays owed for its claim to discharge, or for the next replay. An explicit disarm never defers to a hold (rule 2: it
        // stops the profile whatever started it): an older manual command it could not supersede has committed its
        // reservation, and the stop orders against that claim by receipt; a newer connect still wins, through the bound claim
        // (claimed after it was read) or the newest-start check (claimed with a newer receipt).
        guard admission.kind.isManual || !releaseDefers(id, for: admission) else { throw OnDemandReleaseDeferred() }
        do {
            try await stop(
                profileID: id, connectionUID: intent.ownerUID, reason: .userRequested, retainingSecrets: retains, boundClaim: claim,
                admission: admission,
            )
        } catch is OnDemandCleanupSuperseded { /* A newer connect owns the profile; manual action wins. */ }
        catch let failure as DaemonFailure where failure.kind == .controllerSuperseded {
            /* A newer command claimed an intent after this release's command was received; it wins. */
        }
    }

    /// Whether a manual hold defers the release stop `admission` makes: for a cleanup or a replay, never for an explicit disarm.
    private func releaseDefers(_ id: UUID, for admission: borrowing Admission) -> Bool {
        admission.kind != .disarm && admissions.isHeld(id)
    }

    /// Deletes the bundle unless a retention reason holds (`secretsRetained`). Retention is read inside the profile's ordered
    /// secret writes, after every publication decided before it, and a claim whose publication has not committed yet counts
    /// as retention, so a claim can never land between the check and the deletion.
    func deleteSecretsUnlessRetained(_ id: UUID) async {
        _ = try? await secretWrite(id) { controller in
            guard await !controller.secretsRetained(id) else { return }
            try await controller.secrets.deleteBundle(profileID: id)
        }
    }

    /// Every current retention reason of a profile's secrets (ADR-030 section 7): intended (live or journalled), armed,
    /// start-before-login, or a publication whose claim is still to commit, read from current state, never from a snapshot
    /// taken before it.
    func secretsRetained(_ id: UUID) async -> Bool {
        guard !retainedInMemory(id) else { return true }
        let boot = await bootIntentRetains(id)
        return boot || retainedInMemory(id)
    }

    func retainedInMemory(_ id: UUID) -> Bool {
        intended?.profileID == id || journal.snapshot().intent?.profileID == id || onDemand.armed?.profileID == id
            || publishing[id, default: 0] > 0 || admissions.isHeld(id)
    }

    /// Whether start-before-login is a retention reason for the profile's secrets.
    func bootIntentRetains(_ id: UUID) async -> Bool {
        guard let record = try? await registry.registrationForStart(id, connectionUID: 0) else { return false }
        return record.startBeforeLoginOverride ?? record.registration.profile.macOptions.startBeforeLogin
    }

    // MARK: - Replay

    /// Completes every release the durable record still owes (a crash, or a release that failed), queued after every
    /// reconciliation. The replay is admitted here, synchronously, before anything is read (`scheduleCommand`); the record is
    /// read under that admission, so a boot-time command received after it is newer than every release stop it makes.
    func scheduleReleaseReplay() {
        let id = UUID()
        onDemand.scheduled[id] = scheduleCommand(.replay, profile: nil) { controller, admission in
            await controller.refreshArmedSelection()
            _ = try? await controller.completeReleases(for: admission)
        } finally: { controller in
            controller.finishScheduled(id)
        }
    }
}
