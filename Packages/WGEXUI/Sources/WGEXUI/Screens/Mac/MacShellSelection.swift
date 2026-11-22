// SPDX-License-Identifier: MIT

#if os(macOS)
    import WGEXCore

    public extension MacShellModel {
        var selectedIsInactive: Bool {
            activeProfileID != nil && selectedProfileID != activeProfileID
        }

        var activeProfile: TunnelProfile? {
            profiles.first { $0.id == activeProfileID } ?? selectedProfile
        }

        var detailPresentation: ProtectionPresentation {
            guard selectedIsInactive, !connectionRequestInFlight else { return designPresentation }
            return .inactive(activeTunnel: activeProfile?.name ?? MacStrings.activeTunnel)
        }

        var displayedStatistics: TunnelStatistics? {
            selectedIsInactive ? nil : statistics
        }
    }
#endif
