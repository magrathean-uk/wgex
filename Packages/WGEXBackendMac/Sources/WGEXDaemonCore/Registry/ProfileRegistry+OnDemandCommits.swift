// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXDaemonProtocol

/// ADR-030 on-demand commits (DEC-012): every write of the on-demand record is a compare-and-set under the writing command's
/// admission, in receipt order (`Admission.commit`).
internal extension ProfileRegistry {
    /// Arms `id` in one durable write that also records the release of the profile it replaces and drops any release `id`
    /// was owed (arming is a newer claim). The registration must still be `expected` and compile a macOS rule, and the
    /// commit is the admission's compare-and-set: not superseded, not fenced by a newer stop of `id`, and no newer command
    /// committed the selection, `id` or the replaced profile.
    func armOnDemand(
        _ id: UUID, connectionUID: UInt32, expected: DaemonProfile, admission: borrowing Admission,
    ) async throws -> ArmCommit {
        let record = try registrationForStartUnlocked(id, connectionUID: connectionUID)
        guard record.registration == expected else { throw DaemonFailure.registryRevisionConflict }
        guard Self.armable(record.registration.profile) else { throw DaemonFailure(code: .onDemandNotConfigured) }
        await runCommitPause()
        var scope = AdmissionLedger.Scope(claims: [id], selection: true, decisive: true)
        if let replaced = (try? onDemandRecordUnlocked())?.armed, replaced != id {
            scope.touches = [replaced]
        }
        return try admission.commit(scope) {
            let current = try registrationForStartUnlocked(id, connectionUID: connectionUID)
            guard current.registration == expected else { throw DaemonFailure.registryRevisionConflict }
            var next = try onDemandRecordUnlocked()
            if let replaced = next.armed, replaced != id {
                next.release(replaced, stopsIntent: true)
            }
            next.claim(id)
            next.armed = id
            try writeOnDemand(next)
            return try ArmCommit(selection: selectionUnlocked(), releases: next.releases)
        }
    }

    /// Clears the selection of `id`, recording its release when `stopsIntent` is given; a profile that is not armed is
    /// left alone, and so is one a newer command already decided (the commit is skipped). A record that cannot be read
    /// fails closed: the disarm replaces it with an empty one, which is how the recovery it caused is cleared.
    @discardableResult
    func disarmOnDemand(_ id: UUID, stopsIntent: Bool?, admission: borrowing Admission) async throws -> ArmedSelection {
        try admission.commitIfCurrent(.init(touches: [id])) {
            guard let current = try? onDemandRecordUnlocked() else {
                try writeOnDemand(OnDemandRecord())
                return
            }
            guard current.armed == id else { return }
            var next = current
            next.armed = nil
            if let stopsIntent {
                next.release(id, stopsIntent: stopsIntent)
            }
            try writeOnDemand(next)
        }
        return try selectionUnlocked()
    }

    /// A manual connect of `id` (rules 4 and 5) in one durable write: disarms the armed profile (another one keeps only its
    /// secret retention to drop) and discharges any stop `id` was owed, before the start reserves. The disarm is skipped when
    /// a newer arm already committed the selection (that arm leaves this tunnel alone, rule 6), and the discharge when a
    /// newer command already decided `id`; whatever lands is one commit under the start's admission.
    func manualConnectOnDemand(_ id: UUID, admission: borrowing Admission) async throws -> ArmedSelection {
        try admission.requireLive()
        let armed = try onDemandRecordUnlocked().armed
        var disarm = AdmissionLedger.Scope(selection: true)
        disarm.touches = Set([armed].compactMap(\.self))
        let disarms = admission.passes(disarm)
        let discharges = admission.passes(.init(claims: [id]))
        var scope = AdmissionLedger.Scope(claims: discharges ? [id] : [], selection: disarms)
        if disarms {
            scope.touches = disarm.touches
        }
        _ = try admission.commitIfCurrent(scope) {
            var next = try onDemandRecordUnlocked()
            if disarms {
                if let armed = next.armed, armed != id {
                    next.release(armed, stopsIntent: false)
                }
                next.armed = nil
            }
            if discharges {
                next.dischargeStop(id)
            }
            if try next != onDemandRecordUnlocked() {
                try writeOnDemand(next)
            }
        }
        return try selectionUnlocked()
    }

    /// A newer intent claim on `id` (a boot reservation) discharges the stop it was owed before it reserves.
    func claimOnDemand(_ id: UUID, admission: borrowing Admission) async throws {
        _ = try admission.commitIfCurrent(.init(claims: [id])) { try claimUnlocked(id) }
    }

    func claimUnlocked(_ id: UUID) throws {
        guard var next = try? onDemandRecordUnlocked(), next.releases.contains(where: { $0.profileID == id && $0.stopsIntent })
        else { return }
        next.dischargeStop(id)
        try writeOnDemand(next)
    }

    /// Removes a completed release; one that a newer claim replaced or dropped meanwhile, or that a newer command decided
    /// since, is left as it is.
    func finishRelease(_ release: OnDemandRelease, admission: borrowing Admission) async throws {
        _ = try admission.commitIfCurrent(.init(touches: [release.profileID])) {
            var next = try onDemandRecordUnlocked()
            guard next.releases.contains(release) else { return }
            next.releases.removeAll { $0 == release }
            try writeOnDemand(next)
        }
    }

    /// `registrationForStart` for a start, read in one commit section with its claim (`claiming`, see `claimOnDemand`): nothing
    /// is written once the start's admission is dead, and a claim lands only in receipt order.
    func registrationForStart(
        _ id: UUID, connectionUID: UInt32, claiming: Bool, admission: borrowing Admission,
    ) async throws -> RegisteredProfile {
        guard claiming else {
            guard !admission.isFenced(claiming: id) else { throw AdmissionLedger.superseded }
            return try registrationForStartUnlocked(id, connectionUID: connectionUID)
        }
        // A claim a newer command already decided is skipped; a dead start's claim fails here.
        let claimed = try admission.commitIfCurrent(.init(claims: [id])) {
            let record = try registrationForStartUnlocked(id, connectionUID: connectionUID)
            try claimUnlocked(id)
            return record
        }
        if let claimed {
            return claimed
        }
        try admission.requireLive()
        return try registrationForStartUnlocked(id, connectionUID: connectionUID)
    }
}
