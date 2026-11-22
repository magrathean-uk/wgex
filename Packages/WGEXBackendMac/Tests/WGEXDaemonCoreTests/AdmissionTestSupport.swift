// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Host-test entry points into the controller's internal forms, each under its own admission.
internal extension TunnelController {
    /// A stop through the internal form (for example with a cleanup's `boundClaim`), admitted now.
    @discardableResult
    func testStop(
        profileID: UUID, connectionUID: UInt32, reason: StopReason, boundClaim: UInt64? = nil,
    ) async throws -> Generation {
        try await withCommand(.stop, profile: profileID, input: false) { admission in
            try await stop(
                profileID: profileID, connectionUID: connectionUID, reason: reason, retainingSecrets: false,
                boundClaim: boundClaim, admission: admission,
            )
        }
    }

    /// Records an owed stop of `id` in the durable record alone, as a crash after a disarm's write leaves it.
    func testRecordOwedStop(_ id: UUID) async throws {
        try await withCommand(.recovery, profile: nil, input: false) { admission in
            _ = try await registry.disarmOnDemand(id, stopsIntent: true, admission: admission)
        }
        await refreshArmedSelection()
    }

    /// Enters recovery as an expired operation or a failed startup leaves it.
    func testEnterRecovery() {
        needsRecovery = true
    }

    /// The registry's arm commit alone, under an arm admission taken now (a crash right after the write).
    func testArmCommit(_ id: UUID, uid: UInt32, expected: DaemonProfile) async throws -> ArmCommit {
        try await withCommand(.arm, profile: id, input: false) { admission in
            try await registry.armOnDemand(id, connectionUID: uid, expected: expected, admission: admission)
        }
    }
}
