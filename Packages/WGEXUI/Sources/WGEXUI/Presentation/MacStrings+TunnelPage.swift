// SPDX-License-Identifier: MIT

import Foundation

/// The Mac tunnel page (SPEC 5.2, 5.3): group titles, row labels, values and the status row.
public nonisolated extension MacStrings {
    /// Status row button for a tunnel that is not the active one.
    static let activate = "Activate"
    /// Status row button for the active tunnel.
    static let deactivate = "Deactivate"
    /// Second line while blocked.
    static let trafficBlockedDetail = "The tunnel is down, so the kill switch is blocking all traffic."
    /// Extra status row while blocked.
    static let usingHotelWiFi = "Using hotel or café Wi-Fi?"
    /// Extra status row button while the background service is not answering.
    static let openBackgroundService = "Open Background Service"

    /// Group of live transfer rows.
    static let trafficGroup = "Traffic"
    /// Group of per-peer rows when the tunnel has one server.
    static let serverGroup = "Server"
    /// Group of interface rows.
    static let advancedGroup = "Advanced"

    /// Row label for the latest handshake of any peer.
    static let lastHandshake = "Last handshake"
    /// One row for both directions while the kill switch blocks traffic.
    static let downloadAndUpload = "Download and upload"
    /// Row label for the saved IPv4 addresses.
    static let tunnelAddress = "Tunnel address"
    /// Row label for the saved IPv6 addresses.
    static let ipv6Address = "IPv6 address"
    /// Row label for a peer's saved persistent keepalive.
    static let keepalive = "Keepalive"
    /// Row label for the app-wide Allow local network setting.
    static let localNetwork = "Local network"
    /// Row label and sheet title for the tunnel's on-demand rule.
    static let connectOnDemand = "Connect on demand"
    /// Row label and sheet title for the tunnel's start-up choice.
    static let connectAutomatically = "Connect automatically"
    /// Row label for the interface public key.
    static let thisMacsPublicKey = "This Mac's public key"

    /// Kill switch row: enforcing while the tunnel is up.
    static let killSwitchOn = "On"
    /// Kill switch row: blocking traffic.
    static let killSwitchBlocking = "Blocking"
    /// Kill switch row: suspended for the sign-in window.
    static let killSwitchPaused = "Paused"
    /// Local network row: local traffic is allowed outside the tunnel.
    static let localNetworkAllowed = "Allowed"
    /// Local network row: local traffic is not allowed outside the tunnel.
    static let localNetworkNotAllowed = "Not allowed"
    /// Connect automatically: never.
    static let startupNever = "Never"
    /// Connect automatically: at login.
    static let startupAtLogin = "When I log in"
    /// Connect automatically: before login.
    static let startupAtStartUp = "At start-up"
    /// Explains the start-up choice in its sheet.
    static let startupNote = "\"At start-up\" connects before anyone logs in."
    /// On-demand rule summary for both network types.
    static let onDemandEthernetAndWiFi = "Ethernet and Wi-Fi"

    /// Foot button that opens the editor.
    static let editEllipsis = "Edit…"
    /// Foot button that asks to delete the tunnel.
    static let deleteTunnel = "Delete Tunnel…"

    /// "Connected for 3 h 12 min".
    static func connectedForDuration(_ duration: String) -> String {
        "Connected for \(duration)"
    }

    /// "3 h 12 min".
    static func hoursAndMinutes(_ hours: String, _ minutes: String) -> String {
        "\(hours) h \(minutes) min"
    }

    /// "2 d 4 h".
    static func daysAndHours(_ days: String, _ hours: String) -> String {
        "\(days) d \(hours) h"
    }

    /// "1 hour", "2 hours".
    static func hours(_ count: Int) -> String {
        count == 1 ? "1 hour" : "\(count) hours"
    }

    /// "1 day", "2 days".
    static func days(_ count: Int) -> String {
        count == 1 ? "1 day" : "\(count) days"
    }

    /// "2.4 MB/s · 1.2 GB".
    static func rateAndTotal(_ rate: String, _ total: String) -> String {
        "\(rate) · \(total)"
    }

    /// The sign-in offer's small text, with the Sign-in window setting's minutes.
    static func signInOffer(_ duration: String) -> String {
        "Opens \(duration) without protection so you can reach the sign-in page."
    }

    /// Routes summary for anything but a full route.
    static func routeCount(_ count: Int) -> String {
        count == 1 ? "1 route" : "\(count) routes"
    }

    /// Server group title when the tunnel has several.
    static func serverNumber(_ number: Int) -> String {
        "Server \(number)"
    }

    /// Keepalive row value.
    static func keepaliveEvery(_ seconds: Int) -> String {
        seconds == 1 ? "Every second" : "Every \(seconds) seconds"
    }

    /// On-demand rule summary with an include list.
    static func onDemandOnlyNetworks(_ base: String, _ count: Int) -> String {
        count == 1 ? "\(base), 1 network" : "\(base), \(count) networks"
    }

    /// On-demand rule summary with an exclude list.
    static func onDemandExceptNetworks(_ base: String, _ count: Int) -> String {
        count == 1 ? "\(base), except 1 network" : "\(base), except \(count) networks"
    }
}
