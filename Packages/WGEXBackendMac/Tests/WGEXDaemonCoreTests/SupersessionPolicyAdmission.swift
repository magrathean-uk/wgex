// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol

/// Records the actual typed refusal from the real PF port, independently of controller status events.
internal actor SupersessionPolicyAdmission: DaemonPolicyManaging {
    private let base: PolicyEnforcer
    internal private(set) var slotRefusals: [DaemonFailure] = []
    internal private(set) var cancelledRollbackAdmissions = 0
    internal private(set) var repairCalls = 0
    internal init(base: PolicyEnforcer) {
        self.base = base
    }

    internal func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        let rollback = Task.isCancelled
        do {
            try await base.apply(policy)
            if rollback {
                cancelledRollbackAdmissions += 1
            }
        } catch {
            if error.kind == .tunnelCancelled {
                slotRefusals.append(error)
            }
            throw error
        }
    }

    internal func current() async -> PacketFilterPolicy {
        await base.current()
    }

    internal func setModifiers(_ modifiers: PolicyModifiers) async throws {
        do { try await base.setModifiers(modifiers) }
        catch {
            if error is CancellationError || (error as? DaemonFailure)?.kind == .tunnelCancelled {
                slotRefusals.append(DaemonFailure(code: .tunnelCancelled))
            }
            throw error
        }
    }

    internal func configureProfile(_ profile: TunnelProfile) async throws {
        try await base.configureProfile(profile)
    }

    internal func acquireToken(existing: String?) async throws -> String {
        try await base.acquireToken(existing: existing)
    }

    internal func releaseToken(_ token: String) async throws {
        try await base.releaseToken(token)
    }

    internal func verification() async -> PFVerificationStatus {
        await base.verification()
    }

    internal func verifyEvaluation() async throws {
        try await base.verifyEvaluation()
    }

    internal func repairLiveness(existingToken _: String?, failure: any Error) async throws -> String {
        repairCalls += 1
        throw failure
    }
}
