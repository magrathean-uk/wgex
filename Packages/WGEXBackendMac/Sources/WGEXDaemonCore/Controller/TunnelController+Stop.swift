// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol

internal extension TunnelController {
    /// The stop behind every stop command. `retainingSecrets` keeps an explicit stop from deleting the bundle while another
    /// retention reason holds (start-before-login when on-demand disarms, ADR-030 section 7). `admission` is the admission of
    /// the command the stop belongs to (a cleanup stop borrows its parent's): its receipt, taken before the command's first
    /// suspension, is what the reservation records as ending the intent, and the reservation is refused once a newer command
    /// claimed an intent, so an older stop never stops a newer start. An on-demand stop passes its `ticket` and a cleanup stop
    /// its `boundClaim`; both are re-checked with no suspension before `reserve`. The stop waits only for the lifecycle
    /// operation it replaces. A newer start waits for a command's stop to end (`awaitStopInFlight`); the controller API's
    /// stop is `preemptible` instead, the M1 contract that a newer start cancels it at any suspension.
    @discardableResult
    func stop(
        profileID: UUID, connectionUID: UInt32, reason: StopReason,
        expectedGeneration: Generation? = nil, retainingSecrets: Bool,
        ticket: OnDemandTicket? = nil, boundClaim: UInt64? = nil, admission: borrowing Admission, preemptible: Bool = false,
    ) async throws -> Generation {
        if !needsRecovery {
            guard let owner = try await registry.ownerUID(for: profileID) else { throw DaemonFailure.registryNotFound }
            guard owner == connectionUID else { throw DaemonFailure.registryNotOwner }
        }
        await pauseOnDemand(.stopping(profileID))
        // Read after the owner lookup, so a stop that crossed recovery entry there takes the recovery path.
        if needsRecovery {
            if ticket != nil {
                onDemand.actionDropped = true
                throw CancellationError()
            }
            return try await stopDuringRecovery(
                profileID: profileID, uid: connectionUID, retainingSecrets: retainingSecrets, admission: admission,
            )
        }
        try requireStopAdmission(
            profileID, expectedGeneration: expectedGeneration, ticket: ticket, boundClaim: boundClaim,
        )
        let explicit = reason == .userRequested || reason == .profileRemoved || reason == .uninstall
        // An on-demand stop clears the intent, keeps the secrets and sets no login suspension (ADR-030 section 5).
        let clearsIntent = explicit || reason == .onDemand
        let deletesSecrets = explicit && !retainingSecrets
        let allocated: Generation = if clearsIntent {
            try reserve(intent: nil, deletingSecretsOf: deletesSecrets ? profileID : nil, by: admission)
        } else {
            try reserve(retaining: intended, deletingSecretsOf: deletesSecrets ? profileID : nil, by: admission)
        }
        stoppingProfile = (profileID, allocated)
        let awaited = preemptible ? 0 : 1
        stopsInFlight += awaited
        defer {
            stopsInFlight -= awaited
            if stoppingProfile?.generation == allocated {
                stoppingProfile = nil
            }
        }
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let task = Task { [self] in
            if let previous {
                _ = await previous.result
            }
            try check(allocated)
            try await performStop(profileID: profileID, reason: reason, explicit: deletesSecrets, generation: allocated)
        }
        operation = task
        try await awaitOperation(task, generation: allocated)
        if onDemand.armed?.profileID != profileID {
            scheduleOnDemand(.intentEnded)
        }
        return allocated
    }

    /// The checks with no suspension before a stop's reservation. A cleanup stop of a revoked start (its manual-connect
    /// cleanup) stops nothing.
    private func requireStopAdmission(
        _ profileID: UUID, expectedGeneration: Generation?, ticket: OnDemandTicket?, boundClaim: UInt64?,
    ) throws {
        try checkExpected(expectedGeneration)
        if let boundClaim, boundClaim != intentClaims {
            throw OnDemandCleanupSuperseded()
        }
        guard intended == nil || intended?.profileID == profileID else { throw DaemonFailure.controllerAnotherTunnelActive }
        if let ticket {
            try requireCurrentOnDemandAction(ticket)
        }
    }

    /// Deletes a journalled secret deletion unless a later claim superseded it: arming the profile, enabling its
    /// start-before-login, or starting it removes it from `pendingSecretDeletions`, and a publication whose claim has not
    /// committed yet keeps it. The deletion is one of the profile's ordered secret writes.
    func deletePendingSecrets(_ id: UUID, generation: Generation?) async throws {
        try await secretWrite(id) { controller in
            guard controller.journal.snapshot().pendingSecretDeletions.contains(id), controller.publishing[id, default: 0] == 0
            else { return }
            try await controller.secrets.deleteBundle(profileID: id)
            try controller.journal.mutate(generation: generation) { $0.pendingSecretDeletions.remove(id) }
        }
    }

    /// Appends `write` to the profile's secret writes in this actor turn and waits for it. Writes of one profile run in the
    /// order they were decided; nothing else waits on them, and no command holds anything across them.
    func secretWrite<R: Sendable>(
        _ id: UUID, _ write: @escaping @Sendable (isolated TunnelController) async throws -> R,
    ) async throws -> R {
        let previous = secretWrites[id]
        secretWritesQueued[id, default: 0] += 1
        let task = Task { [self] () async throws -> R in
            await previous?.value
            defer { secretWriteEnded(id) }
            return try await write(self)
        }
        secretWrites[id] = Task { _ = try? await task.value }
        return try await task.value
    }

    private func secretWriteEnded(_ id: UUID) {
        secretWritesQueued[id, default: 1] -= 1
        if secretWritesQueued[id] == 0 {
            secretWritesQueued.removeValue(forKey: id)
            secretWrites.removeValue(forKey: id)
        }
    }

    /// Host tests only: the secret writes of `id` decided and not yet ended (running or queued).
    func pendingSecretWrites(_ id: UUID) -> Int {
        secretWritesQueued[id, default: 0]
    }
}
