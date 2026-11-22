// SPDX-License-Identifier: MIT

import Foundation

/// Daemon connection, registration, approval and secure-install guidance.
public nonisolated extension MacStrings {
    /// Copy used in Mac setup and Settings navigation and the Mac protection controls.
    static let secureInstall = "Secure install"
    /// Copy used in Mac setup and Settings navigation.
    static let hostGuardBackgroundService = "Host guard: background service operations are unavailable outside the VM lab. Use the fake backend to explore setup."
    /// Copy used in Mac shell operation and service status messages.
    static let approveAndStartTheBackground = "Approve and start the background service before secure install."
    /// Copy used in Mac shell operation and service status messages.
    static let addAProfileBeforeChoosingA = "Add a tunnel before choosing a startup option."
    /// Copy used in Mac shell operation and service status messages.
    static let completeSecureInstallBefore = "Complete secure install before enabling activation at boot."
    /// Copy used in Mac shell operation and service status messages.
    static let simulationNoVPNOrSystem = "Simulation: no VPN or system settings are changed."
    /// Reports the connected daemon build number.
    static func daemonConnectedWithBuild(_ build: String) -> String {
        "Background service running, build \(build)."
    }

    /// Copy used in Mac shell operation and service status messages.
    static let connectingToTheDaemon = "Contacting the background service…"
    /// Reports a daemon disconnect with a public reason.
    static func daemonDisconnected(_ reason: String) -> String {
        "Background service unavailable (\(reason))."
    }

    /// Daemon connection description when no public error reason is available.
    static let daemonDisconnectedStatus = "Background service unavailable."
    /// Copy used in Mac Settings.
    static let downgradeState = "Downgrade state"
    /// Copy used in Mac Settings.
    static let downgradeDetected = "Downgrade detected"
    /// Copy used in the Mac onboarding flow.
    static let simulateApproval = "Simulate approval"
    /// Copy used in the status reporter description and the service approval checklist.
    static let backgroundService = "Background service"
    /// Copy used in the secure-install checklist.
    static let checkingSecureInstall = "Checking secure install"
    /// Copy used in the secure-install checklist.
    static let secureInstallVerified = "Secure install verified"
    /// Copy used in the secure-install checklist.
    static let secureInstallNeedsAttention = "Secure install needs attention"
    /// Copy used in the secure-install checklist.
    static let verifyingTheAppLocationAndThe = "Verifying the app location and the privileged service"
    /// Copy used in the secure-install checklist.
    static let wGEXIsInApplicationsAndThe = "WGEX is in Applications and the privileged service matches this app"
    /// Copy used in the secure-install checklist.
    static let moveWGEXToTheApplications = "Move WGEX to the Applications folder. Until then, an administrator account could replace the privileged service"
    /// Copy used in the secure-install checklist.
    static let secureInstallNeededWGEXCanBe = "Secure install needed. WGEX can be changed by another process running as you. Secure the app before activating a tunnel"
    /// Copy used in the secure-install checklist.
    static let thePrivilegedServiceCouldNotBe = "The privileged service could not be verified against this app. Protection cannot be verified until it is"
    /// Copy used in the secure-install checklist.
    static let thePrivilegedServiceIsOlder = "The background service is older than this app. Update it before activating a tunnel"
    /// Copy used in the secure-install checklist.
    static let installInApplications = "Install in Applications"
    /// Copy used in the secure-install checklist.
    static let verifyAgain = "Verify again"
    /// Copy used in the secure-install checklist.
    static let updateService = "Update service"
    /// Copy used in the service approval checklist.
    static let inProgress = "in progress"
    /// Copy used in the service approval checklist.
    static let notStarted = "not started"
    /// Copy used in the service approval checklist.
    static let needsAttention = "needs attention"
    /// Copy used in the service approval checklist.
    static let needsApproval = "Needs approval"
    /// Copy used in the service approval checklist.
    static let approved = "Approved"
    /// Copy used in the service approval checklist.
    static let approval = "Approval"
    /// Copy used in the service approval checklist.
    static let allowWGEXInSystemSettingsUnder = "Allow WGEX in System Settings under Login Items and Extensions"
    /// Copy used in the service approval checklist.
    static let enabled = "Enabled"
    /// Copy used in the service approval checklist.
    static let running = "Running"
    /// Copy used in the service approval checklist.
    static let waitingForTheBackgroundService = "Waiting for the background service to start"
    /// Copy used in the service approval checklist.
    static let registered = "Registered"
    /// Copy used in the service approval checklist.
    static let registerTheBackgroundServiceTo = "Register the background service to continue"
    /// Copy used in the service approval checklist.
    static let theBackgroundServiceSLaunchd = "The background service's launchd plist is missing from this copy of WGEX. Reinstall WGEX"
    /// Copy used in the service approval checklist.
    static let openSystemSettings = "Open System Settings"
    /// Copy used in the shared profile editor string facade.
    static let startBeforeLogin = "Start before login"
    /// Copy used in the shared profile editor string facade.
    static let theMacMustBeUnlockedBeforeThe = "The Mac must be unlocked before the encrypted startup disk is available."
    /// Copy used in the shared profile editor string facade.
    static let startingBeforeLoginRequires = "Starting before login requires secure install and storing the key with the background service."
    /// Copy used in Mac shell operation and service status messages.
    static let secureInstallNeededSecureThe = "Secure install needed. Secure the app before activating a tunnel."

    /// Uninstall (M05-T10): the Settings > Service control and its confirmation, progress, failure and final screens.
    static let uninstallWGEXEllipsis = "Uninstall WGEX…"
    static let uninstallWGEXQuestion = "Uninstall WGEX?"
    static let uninstallEffects = "The tunnel stops and the kill switch turns off. WGEX removes its firewall rules, routes and DNS settings, the background service and the login item. You will be asked for an administrator's approval."
    static let uninstallKeepsProfiles = "Your tunnels, keys and settings stay on this Mac unless you tick the box."
    static let alsoRemoveProfilesAndSettings = "Also remove tunnels and settings"
    static let uninstallEllipsis = "Uninstall…"
    static let uninstalling = "Uninstalling…"
    static let tryAgain = "Try Again"
    static let notNow = "Not Now"
    static let finishUninstallingWGEX = "Finish uninstalling WGEX?"
    static let finishUninstallExplanation = "WGEX was uninstalled from the command line. Finishing removes the background service and the login item. Your tunnels and keys stay on this Mac."
    static let finishUninstallResumeExplanation = "An uninstall started from the command line did not finish. Finishing completes it and removes the background service and the login item. You will be asked for an administrator's approval."
    static let finishUninstall = "Finish Uninstall"
    static let uninstallDaemonFailed = "The background service could not be uninstalled, so nothing was removed. Try again."
    static let uninstallServiceFailed = "The tunnel and kill switch are off, but the background service or login item could not be removed. Try again."
    static let uninstallAppDataFailed = "The background service is removed, but some tunnels or settings could not be deleted. Try again."
    static let wgexIsUninstalled = "WGEX is uninstalled"
    static let wgexCanBeMovedToTheBin = "You can now move WGEX from the Applications folder to the Bin."
}
