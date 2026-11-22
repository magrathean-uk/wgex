// SPDX-License-Identifier: MIT

import Foundation

/// Packet-filter states of the Mac daemon (02 §4.2, ADR-009).
public enum PacketFilterPolicy: Codable, Sendable, Hashable {
    /// No WGEX rules.
    case disconnected
    /// Block all except loopback, DHCP/NDP, LAN per settings, root DNS to the
    /// underlay resolvers and the endpoint candidates.
    case connecting(resolvers: [String], endpoints: [String])
    /// Tunnel up: pass through `interfaceName` and to the endpoints.
    case connected(interfaceName: String, endpoints: [String])
    /// Blocking during teardown.
    case disconnecting
    /// Blocking after a failure while intent is up.
    case error
    /// Global lockdown.
    case lockdown
    /// Narrowed pass until `expires`.
    case captiveWindow(expires: Date)
}
