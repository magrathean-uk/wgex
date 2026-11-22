// SPDX-License-Identifier: MIT

import Foundation

/// Copy for the standard Mac status menu.
public nonisolated extension MacStrings {
    static let menuUnknown = "Unknown"
    static let menuOpenWGEX = "Open WGEX…"
    static let manageTunnels = "Manage Tunnels…"
    static let importTunnelsFromFile = "Import Tunnels from File…"
    static let menuSignInConfirmation = "Sign In to This Network"
    static let menuSignInWarning = "Opening a sign-in window temporarily allows unprotected web traffic."
    static let menuSignIn = "Sign In to This Network…"
    static let menuEndSignIn = "End Sign-In Now"
    static let menuBlocked = "Kill switch is blocking traffic"
    static let menuSignInOpen = "Sign-in window is open"
    static let menuServiceUnavailable = "Background service is not answering"
    static let menuWaiting = "Waiting for the server to answer"
    static let menuActivating = "Activating…"
    static let menuReconnecting = "Reconnecting…"
    static let menuTrafficBlocked = "Traffic blocked"
    static let menuNotProtected = "Not protected"
    static let menuInterface = "Interface"
    static let menuAddress = "Address"
    static let menuIPv6Address = "IPv6 Address"
    static let menuHandshake = "Handshake"
    static let menuKillSwitch = "Kill Switch"
    static let menuKillSwitchOn = "On"

    static func menuStatus(_ value: String) -> String {
        "Status: \(value)"
    }

    static func menuUnprotected(_ remaining: TimeInterval) -> String {
        "Unprotected for \(UIFormat.countdown(remaining))"
    }

    static func menuDetail(_ label: String, _ value: String) -> String {
        "\(label): \(value)"
    }

    static func menuTransfer(rate: Double?, total: UInt64?) -> String {
        let current = rate.map(UIFormat.rate) ?? unavailable
        let bytes = total.map(UIFormat.bytes) ?? unavailable
        return "\(current) (\(bytes))"
    }
}
