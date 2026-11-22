// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Enforcement controls, captive windows, exclusions and policy consequences.
public nonisolated extension MacStrings {
    /// Copy used in Mac setup and Settings navigation.
    /// Shares the Core captive Window label with other platforms.
    static let captiveWindow = UserStrings.captiveWindow
    /// Copy used in Mac Settings.
    static let text5Minutes = "5 minutes"
    /// Copy used in Mac Settings.
    static let text10Minutes = "10 minutes"
    /// Copy used in Mac Settings.
    static let unprotectedWebTrafficIsAllowed = "Unprotected web traffic is allowed for this duration when you open a sign-in window."
    /// Copy used in Mac Settings.
    static let allowLAN = "Allow local network"
    /// Copy used in the Mac protection controls and the menu extra and main window.
    static let openCaptiveWindow = "Open Sign-In Window…"
    /// Final confirmation action; entry points retain their ellipsis because they open this sheet.
    static let confirmOpenCaptiveWindow = "Open Sign-In Window"
    /// Shares the Core end Captive Window label with other platforms.
    static let endCaptiveWindow = UserStrings.endCaptiveWindow
    /// Copy used in the Mac details grid and the Mac protection controls.
    static let killSwitch = "Kill switch"
    /// Copy used in the Mac onboarding flow and the Mac protection controls.
    static let lockdown = "Lockdown"
    /// Copy used in the Mac protection controls and the shared profile editor string facade.
    static let allowLocalNetwork = "Allow local network"
    /// Copy used in the Mac details grid.
    static let armed = "Armed"
    /// Copy used in the Mac details grid.
    static let blockingTraffic = "Blocking traffic"
    /// Copy used in the Mac details grid.
    static let suspendedDuringCaptiveWindow = "Suspended during sign-in window"
    /// Copy used in the Mac details grid.
    static let offNotConnected = "Off (inactive)"
    /// Explains the remaining unprotected network sign-in duration.
    static func captiveWindowDuration(_ duration: String) -> String {
        "Unprotected for \(duration) to sign in to this network"
    }

    /// Copy used in elapsed-time and byte formatting.
    static let captiveWindowEndedRestoring = "Sign-in window ended. Restoring protection"
    /// Copy used in the routing-policy warning sheet.
    static let readToTheEndToContinue = "Read to the end to continue."
    /// Copy used in the routing-policy warning sheet.
    static let turnOn = "Turn on"
    /// Copy used in the routing-policy warning sheet.
    static let keepOff = "Keep off"
}
