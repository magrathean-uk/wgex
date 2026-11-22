// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Only validated, literal values may enter the renderer or process argv.
public struct PFInterface: Sendable, Hashable {
    public let name: String

    public init(_ name: String) throws {
        guard !name.isEmpty, name.utf8.count < 16,
              name.utf8.allSatisfy({ (48 ... 57).contains($0) || (65 ... 90).contains($0) || (97 ... 122).contains($0) }),
              name.first?.isLetter == true
        else { throw DaemonFailure.pfInvalidInput("interface") }
        self.name = name
    }
}

public struct PFAddress: Sendable, Hashable, Comparable {
    public let range: IPAddressRange
    public var text: String {
        range.address
    }

    public var isIPv6: Bool {
        range.isIPv6
    }

    public init(_ text: String) throws {
        guard !text.contains("/") else { throw DaemonFailure.pfInvalidInput("host address") }
        range = try IPAddressRange(text)
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.text < rhs.text
    }
}

public struct PFEndpoint: Sendable, Hashable, Comparable {
    public enum Transport: String, Sendable, Hashable { case udp, tcp }
    public let address: PFAddress
    public let port: UInt16
    public let transport: Transport

    public init(address: PFAddress, port: UInt16, transport: Transport = .udp) throws {
        guard port > 0 else { throw DaemonFailure.pfInvalidInput("endpoint port") }
        self.address = address
        self.port = port
        self.transport = transport
    }

    /// Seam endpoint spelling: IPv4:port or [IPv6]:port, never a hostname.
    public init(_ text: String) throws {
        let host: String
        let portText: String
        if text.hasPrefix("["), let end = text.firstIndex(of: "]"), text[text.index(after: end)...].hasPrefix(":") {
            host = String(text[text.index(after: text.startIndex) ..< end])
            portText = String(text[text.index(end, offsetBy: 2)...])
        } else {
            let parts = text.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { throw DaemonFailure.pfInvalidInput("endpoint") }
            host = String(parts[0]); portText = String(parts[1])
        }
        guard let port = UInt16(portText), portText.allSatisfy(\.isNumber) else {
            throw DaemonFailure.pfInvalidInput("endpoint port")
        }
        try self.init(address: PFAddress(host), port: port)
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        "\(lhs.address.text):\(lhs.port):\(lhs.transport.rawValue)" < "\(rhs.address.text):\(rhs.port):\(rhs.transport.rawValue)"
    }
}

public enum PFPhase: String, Sendable, CaseIterable {
    case disconnected, connecting, connected, disconnecting, error, lockdown
}

/// Canary target follows the available underlay family; loopback verifies an early-boot blocking anchor.
public enum PFCanaryFamily: Sendable, Equatable {
    /// TEST-NET IPv4 target.
    case ipv4
    /// Documentation IPv6 target.
    case ipv6
    /// No physical primary exists yet.
    case loopback
    /// Literal destination used by both the renderer and the sender.
    public var address: String {
        switch self { case .ipv4: "192.0.2.1"; case .ipv6: "2001:db8::1"; case .loopback: "127.0.0.2" }
    }

    /// Selects the first available physical family without substituting one family's interface for another.
    public static func choose(_ underlay: UnderlaySnapshot) -> Self {
        underlay.v4 != nil ? .ipv4 : (underlay.v6 != nil ? .ipv6 : .loopback)
    }
}

public struct PFModifiers: Sendable, Equatable {
    /// Family selected for the evaluation canary.
    public let canary: PFCanaryFamily
    public let allowLAN: Bool
    public let captiveWindow: Bool
    public let ipv6Policy: IPv6Policy
    public let appleServices: AppleServiceRouteTo?
    public let ipv6Underlay: PFInterface?
    /// The intended tunnel's excluded destinations (DEC-087): canonical, sorted, never a default route. Passed on the
    /// physical interface like the "Allow local network" ranges.
    public let exclusions: [IPAddressRange]
    /// The intended tunnel's excluded local ports (DEC-126), sorted and deduplicated: passed on the physical interface
    /// only to and from that interface's own addresses, for apps bound to it.
    public let exclusionPorts: [PortExclusion]

    public init(
        allowLAN: Bool = false, captiveWindow: Bool = false, ipv6Policy: IPv6Policy = .tunnel,
        appleServices: AppleServiceRouteTo? = nil,
        ipv6Underlay: PFInterface? = nil, canary: PFCanaryFamily = .ipv4, exclusions: [IPAddressRange] = [],
        exclusionPorts: [PortExclusion] = [],
    ) {
        self.canary = canary
        self.exclusions = Array(Set(exclusions.filter { $0.prefixLength > 0 }.map(\.network))).sorted()
        self.exclusionPorts = Array(Set(exclusionPorts)).sorted()
        self.allowLAN = allowLAN
        self.captiveWindow = captiveWindow
        self.ipv6Policy = ipv6Policy; self.appleServices = appleServices
        self.ipv6Underlay = ipv6Underlay
    }
}

/// Values supplied by the underlay/controller, never discovered by the renderer.
public struct PFContext: Sendable {
    public let underlay: PFInterface
    public let tunnel: PFInterface?
    public let endpoints: [PFEndpoint]
    public let resolvers: [PFAddress]
    public let tunnelDNS: [PFAddress]
    public let lanTunnelDNS: [PFAddress]
    public let lanSubnets: [IPAddressRange]
    public let tunnelRanges: [IPAddressRange]
    public let consoleUID: UInt32
    #if WGEX_LAB_BUILD
        /// Host-only SSH exception for guest automation; absent from production builds.
        public var labEscapeHatch: PFAddress?
    #endif

    public init(
        underlay: PFInterface, tunnel: PFInterface? = nil, endpoints: [PFEndpoint] = [],
        resolvers: [PFAddress] = [], tunnelDNS: [PFAddress] = [], lanTunnelDNS: [PFAddress] = [],
        lanSubnets: [IPAddressRange] = [], tunnelRanges: [IPAddressRange] = [], consoleUID: UInt32,
    ) throws {
        guard lanSubnets.allSatisfy({ $0.networkPrefixLength > 0 }),
              lanTunnelDNS.allSatisfy({ address in lanSubnets.contains { $0.contains(address.range) } })
        else { throw DaemonFailure.pfInvalidInput("LAN subnet") }
        self.underlay = underlay; self.tunnel = tunnel
        self.endpoints = Array(Set(endpoints)).sorted()
        self.resolvers = Array(Set(resolvers)).sorted()
        self.tunnelDNS = Array(Set(tunnelDNS)).sorted()
        self.lanTunnelDNS = Array(Set(lanTunnelDNS)).sorted()
        self.lanSubnets = Array(Set(lanSubnets.map(\.network))).sorted()
        self.tunnelRanges = Array(Set(tunnelRanges.filter { $0.networkPrefixLength > 0 }.map(\.network) + tunnelDNS.map(\.range))).sorted()
        self.consoleUID = consoleUID
        #if WGEX_LAB_BUILD
            labEscapeHatch = nil
        #endif
    }
}

public struct PFRule: Sendable, Equatable {
    public enum Action: String, Sendable { case pass, block = "block drop" }
    public enum Direction: String, Sendable { case inbound = "in", outbound = "out" }
    public enum Family: String, Sendable { case ipv4 = "inet", ipv6 = "inet6" }
    public enum ProtocolName: String, Sendable { case udp, tcp, icmp, icmp6 }
    public enum Address: Sendable, Equatable {
        /// `interfaceAddress` is the interface's own addresses, `(en0)`, followed by pf as they change.
        case any, literal(String), interfaceNetwork(PFInterface), interfaceAddress(PFInterface)
        public var text: String {
            switch self {
            case .any: "any"
            case let .literal(value): value
            case let .interfaceNetwork(interface): "(\(interface.name):network)"
            case let .interfaceAddress(interface): "(\(interface.name))"
            }
        }
    }

    public let action: Action
    public var direction: Direction?
    public var interface: PFInterface?
    public var family: Family?
    public var proto: ProtocolName?
    public var source: Address = .any
    public var sourcePort: UInt16?
    public var destination: Address = .any
    public var destinationPort: UInt16?
    /// Inclusive upper bound when the port selector is a range (`port 6881:6889`); nil for a single port.
    public var sourcePortEnd: UInt16?
    public var destinationPortEnd: UInt16?
    public var uid: UInt32?
    public var icmpType: UInt8?
    public var keepState = false
    public var label: String?
    public var routeTo: PFInterface?

    package init(_ action: Action) {
        self.action = action
    }
}
