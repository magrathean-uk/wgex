// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    public extension MacShellModel {
        /// Plain-word reason the selected tunnel cannot be activated yet, or nil when nothing blocks it (DEC-088: a tunnel saved
        /// without an address or a server). The tunnel page shows it under the status row; it blocks only Activate.
        var activationBlocker: String? {
            selectedProfile.flatMap(activationBlocker)
        }

        /// The same reason for any tunnel: the menu and the login start use it for the tunnel they would start.
        func activationBlocker(_ profile: TunnelProfile) -> String? {
            canActivate(profile) ? nil : MacStrings.activationNeedsAddressAndServer
        }

        /// Whether `profile` may be activated, armed or chosen for start-up: it has an address and a server, or this shell
        /// does not hold tunnels saved incomplete (`refusesIncompleteTunnels`).
        func canActivate(_ profile: TunnelProfile) -> Bool {
            !refusesIncompleteTunnels || profile.isComplete
        }

        /// False, with the reason as the window's message, when `profile` cannot be activated yet.
        package func admitsActivation(_ profile: TunnelProfile) -> Bool {
            guard let blocker = activationBlocker(profile) else { return true }
            operationMessage = blocker
            return false
        }

        /// Whether deleting `profile` deactivates it first (SPEC 6.4): it is the active tunnel and up or coming up, which
        /// includes Activating, Reconnecting and the sign-in window, or a start for it is still in flight.
        func deletionDeactivatesFirst(_ profile: TunnelProfile) -> Bool {
            if pendingAction == .connecting(profile.id) {
                return true
            }
            return activeProfileID == profile.id && status.phase.generation != nil
        }
    }
#endif
