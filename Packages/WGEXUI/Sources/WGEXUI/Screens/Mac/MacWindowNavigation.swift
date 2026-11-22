// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    public enum MacWindowSelection: Hashable, Sendable {
        case tunnel(UUID), settings(MacSettingsTab)
    }

    public enum MacWindowEntryPoint: CaseIterable, Equatable, Sendable {
        case manageTunnels, about, settings, setup, importTunnel, reopen
    }

    public extension MacShellModel {
        /// Settings navigation leaves the selected tunnel intact for a return to Manage Tunnels.
        var windowSelection: MacWindowSelection? {
            get { showsSettings ? .settings(settingsTab) : selectedProfileID.map(MacWindowSelection.tunnel) }
            set {
                switch newValue {
                case let .tunnel(id):
                    guard canSelectProfile, profiles.contains(where: { $0.id == id }) else { return }
                    selectedProfileID = id
                    tunnelChosen = true
                    showsSettings = false
                case let .settings(tab):
                    guard MacSettingsTab.sidebarPages.contains(tab) else { return }
                    settingsTab = tab
                    showsSettings = true
                case nil: break
                }
            }
        }

        func routeWindow(_ entry: MacWindowEntryPoint) {
            if entry != .setup, entry != .reopen {
                showsOnboarding = false
            }
            switch entry {
            case .manageTunnels:
                showsSettings = false
                applyInitialTunnel()
            case .importTunnel: showsSettings = false
            case .about: windowSelection = .settings(.about)
            case .settings: windowSelection = .settings(.general)
            case .setup:
                revisit(.welcome)
                showsSettings = false
                showsOnboarding = true
            case .reopen: applyInitialTunnel()
            }
        }

        /// SPEC 5.1: the window opens on the active tunnel, else the default tunnel, else the first, else the empty
        /// page. The default is the tunnel set to connect automatically (at login or at start-up), the only stored
        /// default today.
        var initialTunnelID: UUID? {
            if let activeProfileID, profiles.contains(where: { $0.id == activeProfileID }) {
                return activeProfileID
            }
            let isDefault = { (profile: TunnelProfile) in profile.macOptions.autoConnectAtLogin || profile.macOptions.startBeforeLogin }
            return (profiles.first(where: isDefault) ?? profiles.first)?.id
        }

        /// Applied once profiles load (or reload after a failed load), again on the first daemon report, and on each
        /// Manage Tunnels or Dock open. It only replaces no selection or its own earlier choice: a tunnel picked in
        /// the sidebar or selected by an action (selectByAction) is kept, and a command in flight is never
        /// re-targeted. The client's own snapshots (the unreported launch seed StatusBroadcast replays, an unreachable
        /// daemon) name no active tunnel, so only a daemon measurement, fresh or kept as the last report, settles the
        /// destination; one arriving while a command is in flight leaves it to the next.
        func applyInitialTunnelOnFirstReport(_ update: TunnelStatus) {
            guard !initialReportApplied, simulated || update.measuredAt != nil || update.lastReportedAt != nil,
                  !busy, pendingAction == nil else { return }
            initialReportApplied = true
            applyInitialTunnel()
        }

        func applyInitialTunnel() {
            guard !tunnelChosen, canSelectProfile,
                  selectedProfileID == nil || selectedProfileID == ruleSelectedProfileID else { return }
            selectedProfileID = initialTunnelID
            ruleSelectedProfileID = selectedProfileID
        }

        /// An action (import, a saved edit of the open tunnel, a menu start, connect at login) selects its tunnel. The
        /// rule never replaces it afterwards, even when it is the tunnel the rule had chosen.
        func selectByAction(_ id: UUID) {
            selectedProfileID = id
            ruleSelectedProfileID = nil
        }

        /// A profile reload that drops the selected tunnel (or finds none, after a failed launch load) applies the rule
        /// again with the active tunnel already known; the first tunnel when the rule may not (a pick, a command in flight).
        func reselectAfterReload() {
            guard !profiles.contains(where: { $0.id == selectedProfileID }) else { return }
            selectedProfileID = nil
            applyInitialTunnel()
            if selectedProfileID == nil {
                selectedProfileID = profiles.first?.id
            }
        }

        /// Inactive tunnels have no annotation. A pending start takes priority over the last status report.
        func sidebarState(_ profile: TunnelProfile) -> String? {
            if isStarting(profile) {
                return MacStrings.menuActivating
            }
            guard profile.id == activeProfileID else { return nil }
            return tunnelState.sidebarWord
        }
    }
#endif
