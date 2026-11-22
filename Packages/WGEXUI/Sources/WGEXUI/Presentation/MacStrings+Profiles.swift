// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Tunnel selection, empty states and peer endpoint summaries.
public nonisolated extension MacStrings {
    /// Copy used in the Mac protection controls.
    static let defaultTunnel = "Default tunnel"
    /// Copy used in the Mac protection controls.
    static let chooseATunnel = "Choose a tunnel"
    /// Shares the Core tunnels label with other platforms.
    static let tunnels = UserStrings.tunnels
    /// Heading of the main window empty state.
    static let noTunnelsTitle = "No Tunnels"
    /// Summarises peers when no endpoint has been configured.
    static func peersNoEndpoint(_ count: String) -> String {
        "\(count) peers, no endpoint"
    }

    /// Copy used in the menu extra and main window and shared profile rows.
    static let noEndpoint = "No endpoint"
    /// Summarises an endpoint and one additional peer.
    static func endpointWithOneMorePeer(_ endpoint: String) -> String {
        "\(endpoint) and 1 more peer"
    }

    /// Summarises an endpoint and the additional peer count.
    static func endpointWithMorePeers(_ endpoint: String, _ count: String) -> String {
        "\(endpoint) and \(count) more peers"
    }

    /// Sidebar heading from the Mac copy deck.
    static let profiles = "Tunnels"
    /// Names the profile and its state so VoiceOver's item chooser can distinguish inactive rows.
    static func profileRowLabel(_ name: String, state: String) -> String {
        "\(name), \(state)"
    }
}
