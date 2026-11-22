// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// The startup sweep of unclaimed bundles (M05-T02). A crash between superseding an older journalled deletion and writing
/// the claim that retains the bundle (start-before-login, an arm) leaves a bundle on disk that nothing refers to; the
/// journalled-deletion replay no longer names it. Reconciliation runs this sweep after that replay and the purge replay,
/// before it commits and schedules the daemon-start evaluation, so on-demand rules are never evaluated before it.
internal extension TunnelController {
    /// What retains a stored bundle at startup (ADR-030 section 7).
    enum BundleClaim: Equatable {
        /// A retention reason holds: an intent (live or journalled), the armed record, start-before-login, a publication
        /// whose claim is still to commit, or a command holding the profile.
        case claimed
        /// No retention reason holds, and none could be missed: the registration and the on-demand record were read.
        case unclaimed
        /// The on-demand record or the profile's registration could not be read; the bundle is left alone.
        case unreadable
    }

    /// Removes every stored bundle with no claim. A claimed bundle is never touched; one whose claim cannot be read is kept
    /// and logged. Each removal logs one line naming the profile id, never key material. With nothing on disk to remove it
    /// logs nothing. Each check and removal is one of the profile's ordered secret writes, so a publication decided before
    /// it has landed and its claim is read after it.
    func sweepUnclaimedBundles(controlID: UUID) async throws {
        let stored: [UUID]
        do { stored = try await secrets.storedBundleProfileIDs() }
        catch {
            operationLog("bundle sweep: bundle directory unreadable; nothing removed")
            return
        }
        try requireStartupStage(controlID)
        for profileID in stored {
            try await secretWrite(profileID) { controller in
                let claim = await controller.bundleClaim(profileID)
                try controller.requireStartupStage(controlID)
                switch claim {
                case .claimed:
                    return
                case .unreadable:
                    controller.operationLog("bundle sweep: kept bundle \(profileID.uuidString); claim state unreadable")
                case .unclaimed:
                    do {
                        try await controller.secrets.deleteBundle(profileID: profileID)
                        controller.operationLog("bundle sweep: removed unclaimed bundle \(profileID.uuidString)")
                    } catch {
                        controller.operationLog("bundle sweep: could not remove unclaimed bundle \(profileID.uuidString)")
                    }
                }
            }
            try requireStartupStage(controlID)
        }
    }

    /// The bundle's claim, read from current state: memory first, then the durable on-demand record and the registration.
    /// An unregistered profile has no start-before-login and is armed only if the record names it.
    func bundleClaim(_ id: UUID) async -> BundleClaim {
        guard !retainedInMemory(id) else { return .claimed }
        do {
            if try await registry.onDemandRecordUnlocked().armed == id {
                return .claimed
            }
        } catch { return .unreadable }
        do {
            let record = try await registry.registrationForStart(id, connectionUID: 0)
            if record.startBeforeLoginOverride ?? record.registration.profile.macOptions.startBeforeLogin {
                return .claimed
            }
        } catch DaemonFailure.registryNotFound { /* No registration: no start-before-login claim. */ }
        catch { return .unreadable }
        return retainedInMemory(id) ? .claimed : .unclaimed
    }
}
