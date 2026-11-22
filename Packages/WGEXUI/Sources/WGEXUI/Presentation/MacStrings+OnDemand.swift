// SPDX-License-Identifier: MIT

/// On-demand activation on macOS (ADR-030): editor, status, menu and pending-command copy.
public nonisolated extension MacStrings {
    /// Heading of the editor section.
    static let onDemandSection = "On-demand activation"
    /// What the section does and where the rules run.
    static let onDemandExplainer = "WGEX activates and deactivates this tunnel by network. The background service applies the rules, also while WGEX is closed."
    /// Neither network type is selected.
    static let onDemandOffNote = "Choose Ethernet, Wi-Fi or both to turn on-demand on."
    /// Checkbox for wired networks.
    static let onDemandEthernet = "Ethernet"
    /// Checkbox for Wi-Fi networks.
    static let onDemandWiFi = "Wi-Fi"
    /// Picker title for the Wi-Fi network match.
    static let onDemandNetworks = "Wi-Fi networks"
    /// Match every Wi-Fi network.
    static let onDemandAnyNetwork = "Any network"
    /// Match only the listed networks.
    static let onDemandOnlyNetworks = "Only these networks"
    /// Match every network except the listed ones.
    static let onDemandExceptNetworks = "Except these networks"
    /// Text field title for one network name.
    static let onDemandNetworkName = "Network name"
    /// Adds the typed network name to the list.
    static let onDemandAddNetwork = "Add network"
    /// Reads the connected network through CoreWLAN.
    static let onDemandAddConnected = "Add connected network"
    /// Removes one listed network.
    static let onDemandRemoveNetwork = "Remove network"
    /// An include or exclude list has no entry; it is saved as any network (ADR-030 section 2).
    static let onDemandEmptyListNote = "No network is listed, so this saves as Any network. Add a network name to match only or except some."
    /// SSID byte bounds from ADR-030.
    static let onDemandNameLength = "A network name is 1 to 32 bytes long."
    /// Control characters are refused.
    static let onDemandNameControl = "A network name cannot contain control characters."
    /// Each name once.
    static let onDemandNameDuplicate = "Each network name can be listed once."
    /// List bound from ADR-030.
    static let onDemandListLimit = "A list holds at most 64 networks."
    /// Why a Wi-Fi name list needs Location.
    static let onDemandLocationNote = "Matching Wi-Fi network names needs Location access for WGEX, and WGEX must be open to read the name. Without a reading, an excluded list connects everywhere and an included list leaves the tunnel as it is."
    /// Lockdown takes precedence (ADR-030 section 7).
    static let onDemandLockdownNote = "With Lockdown on, networks where on-demand keeps the tunnel off have no connectivity."
    /// Outcome of "Add connected network".
    static let onDemandConnectedNotWiFi = "This Mac is not connected to Wi-Fi."
    /// Outcome when Location is denied or undecided.
    static let onDemandConnectedNeedsLocation = "Allow Location for WGEX in System Settings, Privacy and Security, to read the network name."
    /// Outcome when CoreWLAN returned no name.
    static let onDemandConnectedUnreadable = "The network name could not be read."
    /// Outcome when the network is already listed.
    static let onDemandConnectedAlreadyListed = "That network is already listed."

    /// Window and menu heading when armed.
    static let onDemandArmed = "On-demand armed"
    /// Armed and the current tunnel was brought up by on-demand.
    static let onDemandArmedActivated = "On-demand armed, tunnel brought up by on-demand"
    /// Not armed.
    static let onDemandNotArmed = "On-demand off"
    /// Not armed, but the current tunnel was brought up by on-demand and kept up when the rule was turned off.
    static let onDemandNotArmedActivated = "On-demand off, tunnel brought up by on-demand"
    /// Why that tunnel is still up (ADR-030 section 6 rule 7) and how to end it.
    static let onDemandStayedUp = "On-demand is off for this tunnel, so it stays active until you deactivate it."
    /// Toggle title in the window and the menu.
    static let onDemandToggle = "On-demand"
    /// Status caption for a connect decision.
    static let onDemandDecisionConnect = "This network activates the tunnel."
    /// Status caption for a disconnect decision.
    static let onDemandDecisionDisconnect = "This network keeps the tunnel off."
    /// Status caption without a network.
    static let onDemandHoldNoNetwork = "No network. The tunnel keeps its state."
    /// Status caption while another tunnel is up.
    static let onDemandHoldAnotherTunnel = "Another tunnel is active. This one waits."
    /// Status caption before the first evaluation.
    static let onDemandNoEvaluation = "Waiting for the first network check."
    /// Status caption while the service waits for the app's Wi-Fi reading.
    static let onDemandSettling = "Reading the Wi-Fi network name."
    /// Wi-Fi name unavailable: no app reporting.
    static let onDemandNameNoReporter = "The tunnel keeps its state. Open WGEX so it can read the Wi-Fi network name."
    /// Wi-Fi name unavailable: Location.
    static let onDemandNameNotAuthorised = "The tunnel keeps its state. Allow Location for WGEX to read the Wi-Fi network name."
    /// Wi-Fi name unavailable: timeout.
    static let onDemandNameTimedOut = "The tunnel keeps its state. WGEX did not report the Wi-Fi network name in time."
    /// Wi-Fi name unavailable: unreadable.
    static let onDemandNameUnreadable = "The tunnel keeps its state. The Wi-Fi network name could not be read."
    /// Excluded list, name unavailable: no app reporting. The tunnel connects (ADR-030 section 4).
    static let onDemandConnectNameNoReporter = "This network activates the tunnel because its Wi-Fi name cannot be checked against the excluded list. Open WGEX so it can read the name."
    /// Excluded list, name unavailable: Location.
    static let onDemandConnectNameNotAuthorised = "This network activates the tunnel because its Wi-Fi name cannot be checked against the excluded list. Allow Location for WGEX in System Settings, Privacy and Security, to read the name."
    /// Excluded list, name unavailable: timeout.
    static let onDemandConnectNameTimedOut = "This network activates the tunnel because its Wi-Fi name cannot be checked against the excluded list. WGEX did not report the name in time, so keep WGEX open."
    /// Excluded list, name unavailable: unreadable.
    static let onDemandConnectNameUnreadable = "This network activates the tunnel because its Wi-Fi name cannot be checked against the excluded list. The name could not be read, so check that Location is allowed for WGEX and rejoin the network."
    /// Evaluation paused: owner not signed in.
    static let onDemandPausedOwner = "Paused until the tunnel owner is signed in."
    /// Evaluation paused: recovery.
    static let onDemandPausedRecovering = "Paused while the service recovers."
    /// Evaluation paused: cutover.
    static let onDemandPausedCutover = "Paused while a cutover is armed."

    /// Primary control of a profile with a rule that is not armed (the official app's "Enable On-Demand", in the Mac copy deck's
    /// lower-case form).
    static let enableOnDemand = "Enable on-demand"
    /// Primary control of an armed profile whose tunnel is down.
    static let disableOnDemand = "Disable on-demand"
    /// Primary control of an armed profile whose tunnel is up or connecting.
    static let disableOnDemandAndDeactivate = "Disable on-demand and deactivate"

    /// Pending command: arming.
    static let pendingArming = "Arming on-demand"
    /// Pending command: disarming and disconnecting.
    static let pendingDisarming = "Disarming on-demand and deactivating"
    /// Pending command: connecting.
    static let pendingConnecting = "Activating"
    /// Pending command: disconnecting.
    static let pendingDisconnecting = "Deactivating"
    /// Explains a command that waits for a running stop.
    static let pendingWaitingForStop = "Waiting for the current deactivation to finish. This command runs next."
    /// Row line for a start that waits for a running stop.
    static let pendingWaitingForStopShort = "Waiting for the current deactivation to finish."
    /// Explains a command in flight.
    static let pendingWorking = "Waiting for the background service."

    /// Heading when arming is refused.
    static let onDemandNotConfiguredTitle = "On-demand is not set up"
    /// Consequence of the refused arm.
    static let onDemandNotConfiguredConsequence = "This profile has no on-demand rule, so it cannot be armed."
    /// Recovery for the refused arm.
    static let onDemandNotConfiguredAction = "Open the profile editor, choose Ethernet or Wi-Fi under on-demand activation, save, then arm it again."

    /// The refused-arm copy as one catalogue row.
    static var onDemandNotConfiguredRow: (String, String, String) {
        (onDemandNotConfiguredTitle, onDemandNotConfiguredConsequence, onDemandNotConfiguredAction)
    }

    /// Accessible label of the toggle for one profile.
    static func onDemandToggleLabel(_ profile: String) -> String {
        "On-demand for \(profile)"
    }

    /// Static copy for the string regression suite.
    static let onDemandCatalogue: [String] = [
        onDemandSection, onDemandExplainer, onDemandOffNote, onDemandEthernet, onDemandWiFi, onDemandNetworks, onDemandAnyNetwork,
        onDemandOnlyNetworks, onDemandExceptNetworks, onDemandNetworkName, onDemandAddNetwork, onDemandAddConnected,
        onDemandRemoveNetwork, onDemandEmptyListNote, onDemandNameLength, onDemandNameControl, onDemandNameDuplicate, onDemandListLimit,
        onDemandLocationNote, onDemandLockdownNote, onDemandConnectedNotWiFi, onDemandConnectedNeedsLocation,
        onDemandConnectedUnreadable, onDemandConnectedAlreadyListed, onDemandArmed, onDemandArmedActivated, onDemandNotArmed,
        onDemandNotArmedActivated, onDemandStayedUp, onDemandToggle, onDemandDecisionConnect, onDemandDecisionDisconnect,
        onDemandHoldNoNetwork, onDemandHoldAnotherTunnel, onDemandNoEvaluation, onDemandSettling, onDemandNameNoReporter,
        onDemandNameNotAuthorised, onDemandNameTimedOut, onDemandNameUnreadable, onDemandConnectNameNoReporter,
        onDemandConnectNameNotAuthorised, onDemandConnectNameTimedOut, onDemandConnectNameUnreadable, onDemandPausedOwner,
        onDemandPausedRecovering, onDemandPausedCutover, enableOnDemand, disableOnDemand, disableOnDemandAndDeactivate,
        pendingArming,
        pendingDisarming, pendingConnecting, pendingDisconnecting, pendingWaitingForStop, pendingWaitingForStopShort, pendingWorking,
        onDemandNotConfiguredTitle, onDemandNotConfiguredConsequence, onDemandNotConfiguredAction,
    ]
}
