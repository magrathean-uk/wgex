// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Adds token-preserving enable repair without changing the existing enforcer API.
public struct PolicyLivenessAdapter: DaemonPolicyManaging {
    private let policy: PolicyEnforcer
    private let runner: PFCtl
    public init(policy: PolicyEnforcer, runner: PFCtl) {
        self.policy = policy; self.runner = runner
    }

    public func apply(_ value: PacketFilterPolicy) async throws(DaemonFailure) {
        try await policy.apply(value)
    }

    public func current() async -> PacketFilterPolicy {
        await policy.current()
    }

    public func setModifiers(_ modifiers: PolicyModifiers) async throws {
        try await policy.setModifiers(modifiers)
    }

    public func configureProfile(_ profile: TunnelProfile) async throws {
        try await policy.configureProfile(profile)
    }

    public func acquireToken(existing: String?) async throws -> String {
        try await policy.acquireToken(existing: existing)
    }

    public func releaseToken(_ token: String) async throws {
        try await policy.releaseToken(token)
    }

    public func verification() async -> PFVerificationStatus {
        await policy.verification()
    }

    public func verifyEvaluation() async throws {
        try await policy.verifyEvaluation()
    }

    public func repairLiveness(existingToken: String?, failure _: any Error = DaemonFailure.pfVerification) async throws -> String {
        try await policy.repairLiveness()
    }
}
