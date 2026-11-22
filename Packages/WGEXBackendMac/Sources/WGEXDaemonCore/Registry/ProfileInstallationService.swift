// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

/// Installation ports serialise daemon-owned revisions through the registry and recovery barrier.
public extension TunnelController {
    /// Applies the same request-admission, generation and recovery barriers as legacy installation. The uninstall fence
    /// refuses an install, and one it revoked in flight reports the fence rather than a profile fault (M05-T07).
    func installProfileCAS(_ profile: TunnelProfile, expectedRevision: UInt64?, context: DaemonRequestContext) async -> Reply {
        let refused = Reply.error(.uninstallFailed(step: .admission))
        guard !uninstallFenced else { return refused }
        let reply = await admittedInstall(profile, expectedRevision: expectedRevision, context: context)
        if case .error = reply, uninstallFenced {
            return refused
        }
        return reply
    }

    private func admittedInstall(_ profile: TunnelProfile, expectedRevision: UInt64?, context: DaemonRequestContext) async -> Reply {
        do {
            try requireCutoverRegistryAdmission()
            guard acceptingRequests else { throw DaemonFailure.controllerRecoveryRequired }
            try checkExpected(context.expectedGeneration)
            // The install and its on-demand refresh are one control command (ADR-030 rule 7).
            return try await withCommand(.install, profile: profile.id) { admission in
                let accepted: UInt64
                let migration = try await registry.requiresRevisionMigration(profile.id, connectionUID: context.peer.uid)
                try requireCutoverRegistryAdmission()
                if needsRecovery || migration {
                    let result = Mutex<UInt64?>(nil)
                    let lineage = admission.lineage
                    try await repairRegistration { controller in
                        try controller.requireCutoverRegistryAdmission()
                        let revision = try await controller.registry.installProfile(
                            profile,
                            expectedRevision: expectedRevision,
                            connectionUID: context.peer.uid,
                            admission: controller.readmit(lineage),
                        )
                        result.withLock { $0 = revision }
                    }
                    guard let revision = result.withLock({ $0 }) else { throw DaemonError.malformedMessage }
                    accepted = revision
                } else {
                    accepted = try await registry.installProfile(
                        profile, expectedRevision: expectedRevision, connectionUID: context.peer.uid, admission: admission,
                    )
                }
                await secureInstall.invalidate()
                await onDemandProfileChanged(profile.id, admission: admission)
                return .profileRevision(accepted)
            }
        } catch DaemonFailure.registryRevisionConflict {
            let revision = try? await registry.installationRevision(profile.id, connectionUID: context.peer.uid)
            return .profileRevisionConflict(currentRevision: revision)
        } catch DaemonFailure.registryBusy { return .error(.busy) }
        catch DaemonFailure.registryMultipleBootProfiles { return .error(.multipleBootProfiles) }
        catch DaemonFailure.registryNotOwner { return .error(.notAuthorised(.notOwner)) }
        catch let failure as DaemonFailure where failure.kind == .controllerStaleGeneration { return .error(.staleGeneration) }
        catch DaemonFailure.controllerRecoveryRequired { return .error(.recovering) }
        catch { return .error(.tunnel(.invalidConfiguration(.invalidProfile))) }
    }

    /// Reads only the authenticated owner's revision and never discloses cross-user metadata.
    func profileRevision(_ id: UUID, context: DaemonRequestContext) async -> Reply {
        do { return try await .profileRevision(registry.installationRevision(id, connectionUID: context.peer.uid)) }
        catch DaemonFailure.registryNotFound { return .profileRevision(nil) }
        catch DaemonFailure.registryNotOwner { return .error(.notAuthorised(.notOwner)) }
        catch { return .error(.tunnel(.invalidConfiguration(.invalidProfile))) }
    }
}
