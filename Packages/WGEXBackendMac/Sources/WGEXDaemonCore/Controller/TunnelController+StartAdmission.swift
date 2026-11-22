// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol

internal extension TunnelController {
    /// The checks of every start before its reservation, with no lane held: the secure-install check, then the admission's
    /// liveness. A stop of the profile received meanwhile has already superseded the start at its own admission, so the stop
    /// never waits for it; what the start still runs is refused at its next check and at every commit.
    func prepareStart(_ admission: borrowing Admission, profileID: UUID, restarting: TunnelIntent? = nil) async throws {
        try await requireSecureInstall()
        try requireCurrentStart(admission, profileID: profileID, restarting: restarting)
    }

    /// A start never cancels a stop's teardown in flight (a removal's, a switch's): it waits for that stop to end, holding
    /// nothing, and then checks. A stop never waits for a start this way. A cancelled start (a stop cancels the operation a
    /// restart runs in) stops waiting at once and is refused by its checks.
    func awaitStopInFlight() async throws {
        while stopsInFlight > 0 {
            try Task.checkCancellation()
            let id = UUID()
            await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    if Task.isCancelled {
                        continuation.resume()
                    } else {
                        stopWaiters[id] = continuation
                    }
                }
            } onCancel: {
                Task { await self.resumeStopWaiter(id) }
            }
        }
    }

    private func resumeStopWaiter(_ id: UUID) {
        stopWaiters.removeValue(forKey: id)?.resume()
    }

    /// Throws `controllerSuperseded` when the start is dead (superseded, fenced by a newer stop of its profile), a stop
    /// received after it ended the intent, a newer start already reserved, or the restarted intent changed. `reserve(by:)`
    /// repeats the receipt checks with no suspension before the reservation.
    func requireCurrentStart(_ admission: borrowing Admission, profileID: UUID, restarting: TunnelIntent?) throws {
        try admission.requireLive()
        guard !admission.isFenced(claiming: profileID), intentEndedAt < admission.receipt, newestStartAt <= admission.receipt else {
            throw DaemonFailure.controllerSuperseded(by: generation)
        }
        if let restarting, intended != restarting {
            throw DaemonFailure.controllerSuperseded(by: generation)
        }
    }

    /// The app-secret handoff (DEC-012): `body` runs under the command's admission; when it finds no bundle in the daemon
    /// store and the request came without one, the requester's app is asked through `handoff` and `body` runs again with the
    /// supplied bundle under the same admission. The callback holds nothing, so a newer stop, disarm or manual command
    /// received meanwhile supersedes or fences the command, and the continuation is refused at its next check or commit; the
    /// callback never takes a fresh receipt.
    func withAppSecrets<R>(
        _ id: UUID, payload: PendingDaemonSecrets?, handoff: AppSecretsHandoff?, admission: borrowing Admission,
        _ body: (borrowing Admission, PendingDaemonSecrets?) async throws -> R,
    ) async throws -> R {
        do { return try await body(admission, payload) }
        catch where payload == nil && Self.missingSecrets(error) {
            guard let handoff else { throw error }
            try admission.requireLive()
            let supplied = try await Self.pendingSecrets(handoff.request(id))
            defer { supplied?.wipe() }
            try admission.requireLive()
            return try await body(admission, supplied)
        }
    }

    /// Whether a command failed only because the daemon store holds no bundle for the profile.
    static func missingSecrets(_ error: any Error) -> Bool {
        (error as? DaemonFailure) == .controllerSecretsUnavailable || (error as? DaemonError) == .secretsUnavailable
    }

    /// An automatic restart of `intent` (a failed-start retry, a captive-window restoration) with the intent's own origin, so
    /// an on-demand intent stays on-demand and keeps the observed console context. It is derived from the admission that
    /// claimed the intent and carries that receipt: a command received after that claim wins over the restart.
    func restart(_ intent: TunnelIntent, expectedGeneration: Generation) async throws -> Generation {
        guard let parent = intentLineage else { throw DaemonFailure.controllerSuperseded(by: generation) }
        return try await withDerivedCommand(from: parent, kind: .restart, profile: intent.profileID) { admission in
            try await prepareStart(admission, profileID: intent.profileID, restarting: intent)
            return try await start(
                profileID: intent.profileID, connectionUID: intent.ownerUID, secrets: nil, transport: nil,
                expectedGeneration: expectedGeneration, origin: intent.origin ?? .manual, admission: admission, restarting: intent,
            )
        }
    }
}
