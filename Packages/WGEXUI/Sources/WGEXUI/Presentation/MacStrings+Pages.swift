// SPDX-License-Identifier: MIT

/// The Mac app pages (SPEC 8): General, Protection, Background Service, Log and About.
public nonisolated extension MacStrings {
    // MARK: General

    /// General switch: the inverse of the stored Hide Dock icon preference.
    static let showWGEXInTheDock = "Show WGEX in the Dock"
    /// General switch for the stored protection notifications flag.
    static let notifyMeWhenProtectionChanges = "Notify me when protection changes"
    /// General footer.
    static let quittingDoesNotDisconnectTheTunnel = "Quitting WGEX does not deactivate the tunnel."

    // MARK: Protection

    /// Kill switch state row note.
    static let killSwitchNote = "Always on while a tunnel is active. Blocks all traffic if the tunnel drops."
    /// Lockdown switch note.
    static let lockdownNote = "Keeps blocking even after a restart, until a tunnel is up."
    /// Allow local network switch note.
    static let allowLocalNetworkNote = "Printers, AirPlay and file sharing bypass the tunnel."
    /// Picker for how long protection pauses for a Wi-Fi sign-in page.
    static let signInWindow = "Sign-in window"
    /// Sign-in window picker note.
    static let signInWindowNote = "How long protection pauses for a Wi-Fi sign-in page."
    /// Heading of the limits group.
    static let whatWGEXCannotProtect = "What WGEX cannot protect"
    /// First limit.
    static let limitSignInWindow = "During a sign-in window, traffic is unprotected."
    /// Second limit.
    static let limitLocalNetwork = "Local traffic, when allowed, and traffic to exclusions bypass the tunnel."
    /// Third limit.
    static let limitBeforeUnlock = "Before the disk is unlocked at start-up, WGEX is not running."

    // MARK: Background Service

    /// Fact row: whether the background service runs.
    static let serviceFact = "Service"
    /// Fact row: whether Login Items allows the background service.
    static let allowedInSystemSettings = "Allowed in System Settings"
    /// Fact row: the install check.
    static let installedInApplications = "Installed in Applications"
    /// Service fact: enabled, not answering.
    static let serviceNotRunning = "Not running"
    /// Service fact: waiting for the user in Login Items.
    static let serviceWaitingForApproval = "Waiting for approval"
    /// Service fact: not registered.
    static let serviceNotRegistered = "Not registered"
    /// Allowed fact: yes.
    static let factYes = "Yes"
    /// Allowed fact: no.
    static let factNo = "No"
    /// Install fact: verified.
    static let installVerified = "Verified"
    /// Install fact: the check runs.
    static let installChecking = "Checking…"
    /// Install fact: a problem; the reason shows under it.
    static let installNeedsAttention = "Needs attention"
    /// Opens Login Items in System Settings.
    static let openLoginItemsSettings = "Open Login Items Settings…"
    /// Registers the background service, or registers it again.
    static let registerAgain = "Register Again"
    /// Finishes an app update that needs the background service replaced.
    static let finishUpdateEllipsis = "Finish Update…"
    /// Heading of the uninstall group.
    static let uninstallGroup = "Uninstall"
    /// Footnote under Uninstall WGEX….
    static let uninstallFootnote = "Removes the background service from this Mac. Before anything is removed, you choose whether to keep your tunnels."

    // MARK: Log

    /// Segment showing the event list.
    static let logEvents = "Events"
    /// Segment showing the technical log.
    static let logRaw = "Raw"
    /// Log footer.
    static let logFooter = "Newest at the bottom. Diagnostics exports never include private keys."
    /// Events with nothing recorded.
    static let noEventsSinceWGEXStarted = "No events since WGEX started."
    /// Event category: the tunnel itself.
    static let categoryTunnel = "Tunnel"
    /// Event category: the server.
    static let categoryServer = "Server"
    /// Event category: protection.
    static let categoryProtection = "Protection"
    /// Event category: the network.
    static let categoryNetwork = "Network"

    // MARK: About

    /// About: the licence line.
    static let mitLicence = "MIT licence"
    /// About: opens the documentation address configured in the bundle.
    static let documentationLink = "Documentation"
    /// About: version when the bundle has none.
    static let versionDevelopment = "Development"

    /// "Version 1.2 (45)".
    static func versionWithBuild(_ version: String, _ build: String) -> String {
        "Version \(version) (\(build))"
    }
}
