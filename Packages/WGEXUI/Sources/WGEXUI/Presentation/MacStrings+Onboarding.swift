// SPDX-License-Identifier: MIT

import Foundation

/// Setup steps, privacy explanations, startup choices and completion copy.
public nonisolated extension MacStrings {
    /// Copy used in Mac setup and Settings navigation.
    static let off = "Off"
    /// Copy used in Mac setup and Settings navigation and the shared profile editor string facade.
    static let connectAtLogin = "Activate at login"
    /// Copy used in Mac setup and Settings navigation.
    static let connectAtBootBeforeLogin = "Activate at boot before login"
    /// Copy used in Mac setup and Settings navigation and Mac Settings.
    static let automaticFailover = "Automatic failover"
    /// Copy used in the Mac onboarding flow.
    static let back = "Back"
    /// Copy used in the Mac onboarding flow.
    static let continueLabel = "Continue"
    /// Setup step 1 title (SPEC 7).
    static let welcomeToWGEX = "Welcome to WGEX"
    /// Setup step 1 text (SPEC 7).
    static let wgexConnectsThisMacToYourOwnServer = "WGEX connects this Mac to your own WireGuard server. There are no accounts, no provided servers and no analytics."
    /// Setup step 2 title (SPEC 7).
    static let allowWGEXInTheBackground = "Allow WGEX in the Background"
    /// Setup step 2 text (SPEC 7).
    static let wgexKeepsYourTunnelRunning = "WGEX keeps your tunnel running after you close this window. macOS asks you to allow that once."
    /// Setup step 2 button that opens Login Items in System Settings.
    static let openSystemSettingsEllipsis = "Open System Settings…"
    /// Setup step 2 row word while the approved background service has not yet reported in.
    static let startingEllipsis = "Starting…"
    /// Setup step 2 line after macOS refused to register the background service.
    static let backgroundServiceNotRegistered = "macOS did not register the background service."
    /// Setup step 2 line when macOS cannot find the background service in the app.
    static let backgroundServiceNotFound = "macOS cannot find the background service. Move WGEX to Applications."
}
