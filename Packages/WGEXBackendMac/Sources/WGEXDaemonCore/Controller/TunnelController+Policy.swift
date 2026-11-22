// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy

package extension TunnelController {
    func transition(_ phase: TunnelPhase, protection: ProtectionState) {
        if case .idle = phase {
            snapshot.protectionNote = nil
            snapshot.unresolvedExclusions = []
            rotation.awaitingIPv6 = false
        }
        if case .active = phase {
            if maintenanceState.stableActiveSince == nil {
                maintenanceState.stableActiveSince = clock.now
            }
            maintenanceState.retryAt = nil
            snapshot.recoveryFailureReason = nil
        } else {
            resetMaintenanceBackoffIfStable()
            maintenanceState.stableActiveSince = nil
        }
        if case .failed(_, _, false) = phase, intended != nil, maintenanceState.retryAt == nil {
            scheduleMaintenanceRetry()
        }
        snapshot.phase = phase; snapshot.protection = protectionFailureReason == nil ? protection : .unknown
        snapshot.record(TunnelEvent(date: clock.wallNow, kind: .phaseChanged, generation: generation)); publish()
    }

    func resetMaintenanceBackoffIfStable() {
        if let stableActiveSince = maintenanceState.stableActiveSince, clock.now - stableActiveSince >= .seconds(60) {
            maintenanceState.retryAttempt = 0
        }
    }

    func publish() {
        if startup.secureInstallRegressed {
            snapshot.protection = .unknown
        }
        if snapshot.onDemand != nil {
            snapshot.onDemand?.activated = intended?.startedOnDemand == true
        }
        let profileID = intended?.profileID ?? lastProfileID
        let owner = intended?.ownerUID ?? journal.snapshot().protectionOwnerUID
        wireEvents.yield(DaemonServiceEvent(event: .status(snapshot), profileID: profileID, ownerUID: owner))
        if case .failed(_, _, true) = snapshot.phase, let profileID {
            wireEvents.yield(DaemonServiceEvent(
                event: .needsSecrets(profileID: profileID),
                profileID: profileID,
                ownerUID: owner,
            ))
        }
    }

    func applyPolicy(_ policy: PacketFilterPolicy, generation: Generation, recovery: Bool = false) async throws {
        guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
        if !recovery {
            try check(generation)
        }
        let document = journal.snapshot()
        do {
            try await ports.policy.setModifiers(PolicyModifiers(
                allowLAN: policyAllowsLAN, captiveWindow: Self.isCaptive(policy) ? document.captiveWindow : nil,
                consoleUID: intended?.ownerUID, underlay: underlay, exclusions: policyExclusions,
                exclusionPorts: policyExclusionPorts,
            ))
            guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
            // Record the target first; a crash must never restore a former tun pass.
            try journal.mutate(generation: recovery ? nil : generation) { $0.pfPolicy = policy }
            try await ports.policy.apply(policy)
            guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
            if policy != .disconnected, await ports.policy.verification() != Self.expectedVerification(policy) {
                try await ports.policy.verifyEvaluation()
            }
            guard await ports.policy.verification() == Self.expectedVerification(policy) else { throw DaemonFailure.pfVerification }
        } catch {
            guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
            setPolicyFailure(error)
            snapshot.recoveryFailureReason = .blockingPolicyFailed
            snapshot.protection = .unknown
            publish()
            throw Self.policyFailure(error)
        }
        clearPolicyFailure()
        if !recovery {
            try check(generation)
        }
        recordPolicyVerification()
    }

    func verifyNetwork(_ expectation: ProtectionExpectation) async throws {
        do { try await verifyOffActor(expectation) }
        catch {
            if expectation.resources.generation == generation, !(error is CancellationError), snapshot.protectionNote == nil {
                snapshot.protectionNote = .verificationFailed
            }
            throw error
        }
    }

    func verifyPolicy(refresh: Bool = true) async throws {
        if !refresh, await ports.policy.verification() == Self.expectedVerification(journal.snapshot().pfPolicy) {
            return
        }
        let epoch = generation, policy = journal.snapshot().pfPolicy
        let previousReason = snapshot.recoveryFailureReason
        do {
            try await ports.policy.verifyEvaluation()
            guard await ports.policy.verification() == Self.expectedVerification(policy) else { throw DaemonFailure.pfVerification }
            recordPolicyVerification()
        } catch {
            setPolicyFailure(error)
            snapshot.recoveryFailureReason = .blockingPolicyFailed
            snapshot.protection = .unknown; publish()
            try check(epoch)
            let token = try await ports.policy.repairLiveness(existingToken: journal.snapshot().pfToken, failure: error)
            try check(epoch)
            try journal.mutate(generation: generation) { $0.pfToken = token }
            let policy = journal.snapshot().pfPolicy
            try await applyPolicy(policy, generation: generation)
            clearPolicyFailure()
            snapshot.recoveryFailureReason = previousReason == .blockingPolicyFailed ? nil : previousReason
            switch await ports.policy.verification() {
            case .protected: snapshot.protection = .protected
            case .blocked: snapshot.protection = .blocked
            case .captiveWindow:
                if let window = journal.snapshot().captiveWindow {
                    snapshot.protection = .captiveWindow(expires: window.expiresAtWall)
                }
            default: snapshot.protection = .unknown
            }
            publish()
        }
    }

    private static func policyFailure(_ error: any Error) -> any Error {
        if (error as? DaemonFailure) == .portSystem(code: 5) || (error as? DaemonFailure) == .pfVerification {
            return DaemonFailure.controllerPolicyVerificationFailed
        }
        return error
    }

    static var policyFailureMessage: String {
        "WGEX cannot enforce protection. Restart your Mac and open WGEX."
    }

    func setPolicyFailure(_ error: any Error) {
        if snapshot.protectionNote != .ipv6Unavailable {
            snapshot.protectionNote = (error as? DaemonFailure)?.kind == .pfCanaryFailed ? .canaryFailed : .verificationFailed
        }
        if protectionFailureReason == nil || protectionFailureReason == Self.policyFailureMessage {
            protectionFailureReason = Self.policyFailureMessage
        }
    }

    func clearPolicyFailure() {
        if protectionFailureReason == Self.policyFailureMessage {
            protectionFailureReason = nil
            if snapshot.protectionNote == .canaryFailed || snapshot.protectionNote == .verificationFailed {
                snapshot.protectionNote = nil
            }
        }
    }

    /// LAN passes are profile-bound (M1-20). The renderer's tunnel-range block, which keeps a full-tunnel profile's
    /// LAN behind the tunnel, exists only once the intended profile reached the policy port. Until then, as after a
    /// crash before `preparing`, a LAN pass would precede no range block and open the underlay LAN, so the setting
    /// applies only to an intent whose profile the port already holds, or to no intent at all.
    var policyAllowsLAN: Bool {
        guard settings.allowLAN else { return false }
        guard let profileID = intended?.profileID ?? journal.snapshot().intent?.profileID else { return true }
        return policyProfileID == profileID
    }

    static func isCaptive(_ policy: PacketFilterPolicy) -> Bool {
        if case .captiveWindow = policy {
            return true
        }
        return false
    }

    static func expectedVerification(_ policy: PacketFilterPolicy) -> PFVerificationStatus {
        switch policy {
        case .disconnected: .unprotected
        case .connected: .protected
        case .captiveWindow: .captiveWindow
        default: .blocked
        }
    }

    var failurePolicy: PacketFilterPolicy {
        settings.lockdown ? .lockdown : (intended != nil ? .error : .disconnected)
    }

    func withdrawCaptiveException() throws {
        captiveTask?.cancel(); captiveTask = nil
        try journal.mutate(generation: generation) { $0.captiveWindow = nil }
    }

    /// Called only after the current generation's policy verification has succeeded.
    func recordPolicyVerification() {
        snapshot.verifiedAt = clock.wallNow
        snapshot.verifiedAtContinuous = clock.continuousNow
    }

    func acquireToken(_ generation: Generation) async throws {
        do {
            try await ports.policy.setModifiers(PolicyModifiers(
                allowLAN: policyAllowsLAN, captiveWindow: journal.snapshot().captiveWindow,
                consoleUID: intended?.ownerUID, underlay: underlay, exclusions: policyExclusions,
                exclusionPorts: policyExclusionPorts,
            ))
            let token = try await ports.policy.acquireToken(existing: journal.snapshot().pfToken)
            // Retain returned token even if superseded while the adapter was suspended.
            try journal.mutate(generation: nil) { $0.pfToken = token }
            try check(generation)
        } catch {
            if await ports.policy.verification() == .unknown {
                setPolicyFailure(error)
                snapshot.recoveryFailureReason = .blockingPolicyFailed
                snapshot.protection = .unknown; publish()
            }
            throw Self.policyFailure(error)
        }
    }
}

/// Keeps heartbeat observations out of the diagnostics ring without suppressing status delivery.
public struct DaemonDiagnosticChanges: Sendable {
    private struct Scope: Hashable { let profile: UUID?; let owner: UInt32? }
    private var statuses: [Scope: TunnelStatus] = [:]
    private var needsSecrets: Set<Scope> = []
    /// Creates an empty per-owner observation cache.
    public init() {}
    /// Returns true only for a changed snapshot or a new secrets request.
    public mutating func receive(_ event: DaemonServiceEvent) -> Bool {
        let scope = Scope(profile: event.profileID, owner: event.ownerUID)
        switch event.event {
        case let .status(status):
            if let previous = statuses[scope], previous.hasSameState(as: status) {
                return false
            }
            statuses[scope] = status; needsSecrets.remove(scope); return true
        case .needsSecrets: return needsSecrets.insert(scope).inserted
        default: return false
        }
    }
}
