// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// M05-T05: editing or replacing the profile that is itself active, as the official app's `TunnelsManager.modify` does.
    public extension MacShellModel {
        /// Whether a save of `id` applies to a running tunnel: it is the active profile and its tunnel is up or coming up (the
        /// official app's active, activating and reasserting), not stopping.
        func isRunningTunnel(_ id: UUID) -> Bool {
            guard activeProfileID == id, status.phase.generation != nil else { return false }
            if case .stopping = status.phase {
                return false
            }
            return true
        }

        /// Registers a saved edit of the running profile inside the caller's save, which rolls back when this throws.
        func installRunningEdit(_ profile: TunnelProfile) async throws {
            try await backend.install(profile)
        }

        /// Applies a saved edit to the running tunnel as the official app's `modify` does (it stops and restarts the tunnel),
        /// as one start of the same profile: the daemon restarts it in place and holds its blocking policy from before the old
        /// tunnel is dismantled until the new one is connected, so the kill switch never drops in between.
        ///
        /// A start is a manual connect to the daemon and disarms on-demand (ADR-030 section 6 rule 4), but an edit is not a
        /// manual connect: the official app's `modify` keeps on-demand as it was. `rearming` is whether the profile was armed
        /// before the save; it is armed again after the restart when the saved profile still has a rule.
        func restartRunningTunnel(_ profile: TunnelProfile, rearming: Bool) async {
            guard isRunningTunnel(profile.id) else { return }
            connectionRequestInFlight = true
            pendingAction = .connecting(profile.id)
            var started = true
            do { requestedProfileID = profile.id; try await backend.start(profile.id, transport: nil) }
            catch { started = false; reportError(error) }
            connectionRequestInFlight = false
            pendingAction = nil
            guard rearming, isOnDemandConfigured(profile) else { return }
            pendingAction = .arming(profile.id)
            defer { pendingAction = nil }
            do {
                try await operations.armOnDemand(profile)
                try? await daemonHooks.refreshStatus?()
            } catch {
                // After a failed start, only the start's error is shown.
                if started {
                    reportError(error)
                }
            }
        }
    }
#endif
