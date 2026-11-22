// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// A control command the app has sent and the daemon has not yet acknowledged. The daemon serialises control commands
    /// (DEC-008), so one can wait behind a slow stop; the UI names it instead of appearing hung.
    public enum MacPendingAction: Sendable, Equatable {
        case connecting(UUID)
        case disconnecting
        case arming(UUID)
        case disarming(UUID)
    }

    /// What the primary control (window orb and button, toolbar button, menu bar button) does for one profile. For a profile with
    /// an on-demand rule it arms and disarms (ADR-030 section 6 rule 1: the official "Enable On-Demand", "Disable On-Demand" and
    /// "Disable On-Demand and Deactivate"); any other profile keeps the presentation's own action.
    public enum MacPrimaryControl: Sendable, Equatable {
        case action(ProtectionAction)
        case enableOnDemand
        case disableOnDemand
        case disableOnDemandAndDeactivate

        public var title: String {
            switch self {
            case let .action(action): action.title
            case .enableOnDemand: MacStrings.enableOnDemand
            case .disableOnDemand: MacStrings.disableOnDemand
            case .disableOnDemandAndDeactivate: MacStrings.disableOnDemandAndDeactivate
            }
        }

        package var armsOrDisarms: Bool {
            if case .action = self {
                false
            } else {
                true
            }
        }
    }

    /// Armed and activated display of one profile (ADR-030 section 8: armed and active are separate facts).
    public struct MacOnDemandPresentation: Sendable, Equatable {
        /// "On-demand armed", with or without the note that it brought the tunnel up.
        public var title: String
        /// Why the tunnel is in its state, from the daemon's last evaluation. Never an SSID.
        public var detail: String?
        public var isArmed: Bool
        /// The current tunnel was started by on-demand.
        public var activated: Bool
        public var glyph: String
    }

    public extension MacShellModel {
        /// The profile has an on-demand rule the daemon can arm.
        func isOnDemandConfigured(_ profile: TunnelProfile) -> Bool {
            MacOnDemandForm(policy: profile.onDemand).isEnabled
        }

        func isOnDemandArmed(_ profileID: UUID) -> Bool {
            status.onDemand?.armedProfileID == profileID
        }

        /// The armed profile, if any.
        var armedProfile: TunnelProfile? {
            status.onDemand?.armedProfileID.flatMap { id in profiles.first { $0.id == id } }
        }

        /// The daemon says the profile's running tunnel was started by on-demand. Independent of arming: saving the policy as Off
        /// disarms the profile and leaves that tunnel up (ADR-030 section 6 rule 7), and the daemon keeps reporting it.
        func isBroughtUpByOnDemand(_ profileID: UUID) -> Bool {
            status.onDemand?.activated == true && activeProfileID == profileID
        }

        /// Nil for a profile that has no rule, is not armed and did not bring its tunnel up by on-demand.
        func onDemandPresentation(for profile: TunnelProfile) -> MacOnDemandPresentation? {
            let armed = isOnDemandArmed(profile.id)
            let activated = isBroughtUpByOnDemand(profile.id)
            guard armed || activated || isOnDemandConfigured(profile) else { return nil }
            guard armed, let state = status.onDemand else {
                return MacOnDemandPresentation(
                    title: activated ? MacStrings.onDemandNotArmedActivated : MacStrings.onDemandNotArmed,
                    detail: activated ? MacStrings.onDemandStayedUp : nil,
                    isArmed: false, activated: activated, glyph: "bolt.slash",
                )
            }
            return MacOnDemandPresentation(
                title: activated ? MacStrings.onDemandArmedActivated : MacStrings.onDemandArmed,
                detail: Self.onDemandDetail(state),
                isArmed: true, activated: activated, glyph: activated ? "bolt.fill" : "bolt",
            )
        }

        /// The daemon's reason for the tunnel's state under the armed rule.
        internal static func onDemandDetail(_ state: OnDemandStatus) -> String {
            if state.ssid == .settling {
                return MacStrings.onDemandSettling
            }
            guard let decision = state.decision else { return MacStrings.onDemandNoEvaluation }
            switch decision {
            case .connect: return connectDetail(state.ssid)
            case .disconnect: return MacStrings.onDemandDecisionDisconnect
            case .hold(.noNetwork): return MacStrings.onDemandHoldNoNetwork
            case .hold(.anotherTunnelActive): return MacStrings.onDemandHoldAnotherTunnel
            case .hold(.ssidUnavailable): return unavailableDetail(state.ssid)
            case .paused(.ownerNotConsoleUser): return MacStrings.onDemandPausedOwner
            case .paused(.recovering): return MacStrings.onDemandPausedRecovering
            case .paused(.cutoverArmed): return MacStrings.onDemandPausedCutover
            }
        }

        /// A connect decision. With the name unavailable it is an excluded list skipping its disconnect rule (ADR-030 section 4),
        /// so the reason, the consequence and the way out are shown with the outcome.
        private static func connectDetail(_ ssid: OnDemandStatus.SSIDState) -> String {
            guard case let .unavailable(reason) = ssid else { return MacStrings.onDemandDecisionConnect }
            return switch reason {
            case .noReporter: MacStrings.onDemandConnectNameNoReporter
            case .notAuthorised: MacStrings.onDemandConnectNameNotAuthorised
            case .timedOut: MacStrings.onDemandConnectNameTimedOut
            case .unreadable: MacStrings.onDemandConnectNameUnreadable
            }
        }

        /// Why the Wi-Fi network name is unavailable, as the daemon reports it.
        private static func unavailableDetail(_ ssid: OnDemandStatus.SSIDState) -> String {
            guard case let .unavailable(reason) = ssid else { return MacStrings.onDemandNameUnreadable }
            return switch reason {
            case .noReporter: MacStrings.onDemandNameNoReporter
            case .notAuthorised: MacStrings.onDemandNameNotAuthorised
            case .timedOut: MacStrings.onDemandNameTimedOut
            case .unreadable: MacStrings.onDemandNameUnreadable
            }
        }

        /// The primary control for `profile` when the surface would show `action`. Recovery actions (check again, end the captive
        /// window) stay as they are. A profile with a rule that is not armed offers "Enable On-Demand" while its tunnel is down; while
        /// its own tunnel runs or connects without arming (a manual start, or one kept up when the rule went off) the primary
        /// control stays Disconnect or Cancel, so a running tunnel can always be stopped. An armed profile offers "Disable
        /// On-Demand", or "Disable On-Demand and Deactivate" while its own tunnel is up.
        func primaryControl(for profile: TunnelProfile?, action: ProtectionAction) -> MacPrimaryControl {
            guard let profile, !simulated, daemonRunning, action != .checkAgain, action != .endCaptiveWindow else {
                return .action(action)
            }
            if isOnDemandArmed(profile.id) {
                return activeProfileID == profile.id ? .disableOnDemandAndDeactivate : .disableOnDemand
            }
            guard isOnDemandConfigured(profile), canActivate(profile), action == .connect || action == .reconnect,
                  activeProfileID != profile.id
            else { return .action(action) }
            return .enableOnDemand
        }

        /// The window's primary control: the selected profile.
        var windowPrimaryControl: MacPrimaryControl {
            primaryControl(for: selectedProfile, action: detailPresentation.action)
        }

        /// The menu bar's primary control: the running profile, else the selected one.
        var menuPrimaryControl: MacPrimaryControl {
            primaryControl(for: activeProfile, action: designPresentation.action)
        }

        /// Sends the arm or disarm a primary control stands for. False when the control is an ordinary connection action.
        internal func performOnDemandControl(_ control: MacPrimaryControl) async -> Bool {
            guard control.armsOrDisarms else { return false }
            if let profile = selectedProfile {
                await setOnDemand(control == .enableOnDemand, for: profile)
            }
            return true
        }

        /// A click on a profile row in the menu bar: select it and switch to it. A profile with a rule is armed instead of
        /// started, and one that is already armed stays armed (the on-demand toggle disarms it); nothing here starts it by hand.
        func chooseFromMenu(_ profile: TunnelProfile) async {
            selectByAction(profile.id)
            guard profile.id != activeProfileID else { return }
            switch primaryControl(for: profile, action: detailPresentation.action) {
            case .enableOnDemand: await setOnDemand(true, for: profile)
            case .disableOnDemand, .disableOnDemandAndDeactivate: break
            case .action: await toggleConnection()
            }
        }

        /// The toggle can arm only a profile that has a rule; a profile whose rule was turned off while its tunnel stayed up can
        /// only be shown.
        func canToggleOnDemand(_ profile: TunnelProfile) -> Bool {
            canChangeOnDemand && (isOnDemandArmed(profile.id) || isOnDemandConfigured(profile) && canActivate(profile))
        }

        /// Arming and disarming need the real service: not a preview, not under the host guard, not mid-command.
        var canChangeOnDemand: Bool {
            !hostGuarded && !simulated && daemonRunning && !busy && pendingAction == nil
        }

        /// Arms or disarms one profile. Arming installs the current profile first, so the daemon evaluates what the editor
        /// saved; disarming stops the tunnel if it is up (official "Disable On-Demand and Deactivate").
        func setOnDemand(_ armed: Bool, for profile: TunnelProfile) async {
            // An incomplete tunnel (DEC-088) is never installed, so it is never armed.
            guard canChangeOnDemand, !armed || isOnDemandConfigured(profile) && canActivate(profile) else { return }
            pendingAction = armed ? .arming(profile.id) : .disarming(profile.id)
            defer { pendingAction = nil }
            await perform {
                if armed {
                    try await self.backend.install(profile)
                    try await self.operations.armOnDemand(profile)
                } else {
                    try await self.operations.disarmOnDemand(profile.id)
                }
                try? await self.daemonHooks.refreshStatus?()
            }
        }

        private var isStopping: Bool {
            guard case .stopping = status.phase else { return false }
            return true
        }

        /// True while a start for this profile is in flight, including one waiting behind a running stop.
        func isStarting(_ profile: TunnelProfile) -> Bool {
            pendingAction == .connecting(profile.id)
        }

        /// The row's state line for a profile that is not the active one: the start in flight names itself.
        func inactiveRowState(_ profile: TunnelProfile) -> String {
            guard isStarting(profile) else { return MacStrings.inactive }
            return MacStrings.pendingConnecting + "… " + (isStopping ? MacStrings.pendingWaitingForStopShort : MacStrings.pendingWorking)
        }

        /// Copy for the command in flight; says so when it waits behind a running stop.
        var pendingActionText: String? {
            guard let pendingAction else { return nil }
            let title = switch pendingAction {
            case .connecting: MacStrings.pendingConnecting
            case .disconnecting: MacStrings.pendingDisconnecting
            case .arming: MacStrings.pendingArming
            case .disarming: MacStrings.pendingDisarming
            }
            let behindStop = isStopping && pendingAction != .disconnecting
            return title + "… " + (behindStop ? MacStrings.pendingWaitingForStop : MacStrings.pendingWorking)
        }
    }
#endif
