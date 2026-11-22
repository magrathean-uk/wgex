// SPDX-License-Identifier: MIT

import Foundation

/// Direct and relay transport selection, configuration and failover copy.
public nonisolated extension MacStrings {
    /// Copy used in the connection orb and the Mac details grid.
    static let directWireGuard = "Direct WireGuard"
    /// Copy used in the Mac events list and toast and the Mac details grid.
    static let transport = "Transport"
    /// Copy used in the connection orb.
    static let chooseTransport = "Choose transport"
    /// Copy used in Mac setup and Settings navigation and shared platform Settings sections.
    static let transports = "Transports"
    /// Copy used in the shared profile editor string facade.
    static let directWireGuardUDP = "Direct WireGuard (UDP)"
    /// Copy used in shared platform Settings sections.
    static let experimentalRelayTransports = "Experimental: relay transports"
    /// Copy used in shared platform Settings sections.
    static let relayTransportsAreExperimental = "Relay transports are experimental and untested from censored networks."
}
