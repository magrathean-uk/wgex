// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// DEC-126 local-port exclusions on the Mac: packet-filter rules only, rendered and never applied.
@Suite(.timeLimit(.minutes(1)))
private struct ExclusionPortTests {
    private static func context(underlay: String = "en0") throws -> PFContext {
        try PFContext(
            underlay: PFInterface(underlay), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820"), PFEndpoint("[2001:db8::8]:51820")],
            resolvers: [PFAddress("192.168.20.1")], tunnelDNS: [PFAddress("10.77.0.1")],
            lanSubnets: [IPAddressRange("192.168.20.0/24")],
            tunnelRanges: [IPAddressRange("0.0.0.0/0"), IPAddressRange("::/0"), IPAddressRange("10.77.0.0/24")],
            consoleUID: 501,
        )
    }

    private static func ports() throws -> [PortExclusion] {
        try [PortExclusion("6881-6889/udp"), PortExclusion("1911")]
    }

    private static func lines(_ phase: PFPhase, _ modifiers: PFModifiers, underlay: String = "en0") throws -> [String] {
        try PacketFilterRenderer.render(phase: phase, modifiers: modifiers, context: context(underlay: underlay))
            .split(separator: "\n").map(String.init)
    }

    /// Snapshot of the port passes for `1911` (TCP and UDP) and `6881-6889/udp`, sorted by port, per family.
    private static func portLines(v4 en: String = "en0", v6 en6: String = "en0") -> [String] {
        [(en, "inet"), (en6, "inet6")].flatMap { interface, family in
            [
                "pass out quick on \(interface) \(family) proto tcp from (\(interface)) port 1911 to any no state",
                "pass in quick on \(interface) \(family) proto tcp from any to (\(interface)) port 1911 no state",
                "pass out quick on \(interface) \(family) proto udp from (\(interface)) port 1911 to any no state",
                "pass in quick on \(interface) \(family) proto udp from any to (\(interface)) port 1911 no state",
                "pass out quick on \(interface) \(family) proto udp from (\(interface)) port 6881:6889 to any no state",
                "pass in quick on \(interface) \(family) proto udp from any to (\(interface)) port 6881:6889 no state",
            ]
        }
    }

    @Test(arguments: [PFPhase.connecting, .connected, .error, .lockdown])
    func `ports add no-state passes from and to the physical addresses after the DNS blocks`(phase: PFPhase) throws {
        let without = try Self.lines(phase, PFModifiers())
        let with = try Self.lines(phase, PFModifiers(exclusionPorts: Self.ports()))
        let insertion = try #require(without.firstIndex { line in
            line.contains("icmp-type 3") || line.contains("icmp6-type 2") || (line.hasPrefix("block") && line.contains("<wgex_"))
        })
        #expect(with == Array(without[..<insertion]) + Self.portLines() + Array(without[insertion...]))
        let dnsBlock = try #require(with.lastIndex { $0.contains("port 853") && $0.hasPrefix("block") })
        let first = try #require(with.firstIndex(of: Self.portLines()[0]))
        #expect(dnsBlock < first)
        #expect(with.last == "block drop quick all")
    }

    @Test
    func `ports follow the address exclusions and a separate IPv6 underlay, IPv4 and IPv6 snapshots`() throws {
        let excluded = try [IPAddressRange("192.0.2.0/24")]
        let both = try Self.lines(.connected, PFModifiers(exclusions: excluded, exclusionPorts: Self.ports()))
        let address = try #require(both.firstIndex(of: "pass in quick on en0 inet from 192.0.2.0/24 to any no state"))
        #expect(both[address + 1] == Self.portLines()[0])
        // IPv4 on en0, IPv6 on en1: each family names its own interface and that interface's addresses.
        let split = try Self.lines(.connected, PFModifiers(ipv6Underlay: PFInterface("en1"), exclusionPorts: Self.ports()))
        let expected = Self.portLines(v4: "en0", v6: "en1")
        let start = try #require(split.firstIndex(of: expected[0]))
        #expect(Array(split[start ..< start + expected.count]) == expected)
        #expect(!split.contains { $0.contains("inet6") && $0.contains("(en0)") })
        // An IPv6-only underlay (en1 primary) keeps the same shape.
        let v6 = try Self.lines(.connected, PFModifiers(canary: .ipv6, exclusionPorts: Self.ports()), underlay: "en1")
        let v6Expected = Self.portLines(v4: "en1", v6: "en1")
        let v6Start = try #require(v6.firstIndex(of: v6Expected[0]))
        #expect(Array(v6[v6Start ..< v6Start + v6Expected.count]) == v6Expected)
    }

    @Test
    func `no port rule without enforcement, on a loopback canary, in the blocking replacement or without ports`() throws {
        let modifiers = try PFModifiers(exclusionPorts: Self.ports() + Self.ports())
        #expect(try modifiers.exclusionPorts == Self.ports().sorted())
        #expect(try PacketFilterRenderer.render(phase: .disconnected, modifiers: modifiers, context: Self.context()).isEmpty)
        let loopback = try Self.lines(.error, PFModifiers(canary: .loopback, exclusionPorts: Self.ports()))
        #expect(!loopback.contains { $0.contains("port 1911") })
        #expect(try !Self.lines(.connected, PFModifiers()).contains { $0.contains("(en0)") })
        // Rendered text survives the pf read-back comparison (pfctl prints `port = 1911` and `port 6881:6889`).
        let rendered = try PacketFilterRenderer.render(phase: .connected, modifiers: modifiers, context: Self.context())
        let printed = rendered.replacingOccurrences(of: "port 1911", with: "port = 1911")
        #expect(PacketFilterReadback.matches(printed, rendered: rendered))
    }

    /// Render-level check: the first matching quick rule decides. A packet from the tunnel address on the physical
    /// interface stays blocked even on an excluded port; the same port from the physical address passes.
    @Test
    func `a tunnel-sourced packet on the physical interface stays blocked on an excluded port`() throws {
        let rules = try PacketFilterRenderer.rules(
            phase: .connected, modifiers: PFModifiers(exclusionPorts: Self.ports()), context: Self.context(),
        )
        let physical = ["192.168.20.10", "fe80::10"], table = try Self.context().tunnelRanges
        func verdict(_ probe: Probe) -> PFRule.Action? {
            rules.first { $0.matches(probe, physical: physical, table: table) }?.action
        }
        let tunnelOut = Probe(out: true, proto: .udp, source: "10.77.0.2", sourcePort: 1911, destination: "203.0.113.50", port: 6881)
        #expect(verdict(tunnelOut) == .block)
        let tunnelRange = Probe(out: true, proto: .udp, source: "10.77.0.2", sourcePort: 6885, destination: "203.0.113.50", port: 1)
        #expect(verdict(tunnelRange) == .block)
        let tunnelIn = Probe(out: false, proto: .tcp, source: "203.0.113.50", sourcePort: 40000, destination: "10.77.0.2", port: 1911)
        #expect(verdict(tunnelIn) == .block)
        let boundOut = Probe(out: true, proto: .udp, source: "192.168.20.10", sourcePort: 6885, destination: "203.0.113.50", port: 1)
        #expect(verdict(boundOut) == .pass)
        // The lab's p1911-tcp and p1911-udp (M08-T12): pf passes them, so their EHOSTUNREACH was the route, not a rule.
        for proto in [PFRule.ProtocolName.tcp, .udp] {
            let lab = Probe(out: true, proto: proto, source: "192.168.20.10", sourcePort: 1911, destination: "203.0.113.9", port: 50001)
            #expect(verdict(lab) == .pass)
        }
        let boundIn = Probe(out: false, proto: .tcp, source: "203.0.113.50", sourcePort: 40000, destination: "192.168.20.10", port: 1911)
        #expect(verdict(boundIn) == .pass)
        // TCP was not listed for the UDP range, and another port stays blocked.
        let tcpRange = Probe(out: true, proto: .tcp, source: "192.168.20.10", sourcePort: 6885, destination: "203.0.113.50", port: 1)
        #expect(verdict(tcpRange) == .block)
        let other = Probe(out: true, proto: .udp, source: "192.168.20.10", sourcePort: 1912, destination: "203.0.113.50", port: 1)
        #expect(verdict(other) == .block)
        // DNS from an excluded port stays blocked on the physical interface.
        let dns = Probe(out: true, proto: .udp, source: "192.168.20.10", sourcePort: 1911, destination: "203.0.113.53", port: 53)
        #expect(verdict(dns) == .block)
    }
}

/// One IPv4 packet on en0 for the render-level check.
private struct Probe {
    let out: Bool
    let proto: PFRule.ProtocolName
    let source: String
    let sourcePort: UInt16
    let destination: String
    let port: UInt16
}

private extension PFRule {
    /// A deliberately small matcher over the rule fields this check uses; a rule with a field it does not model
    /// (uid, group label, ICMP type, table) is treated as not matching, which only makes a pass verdict harder to reach.
    func matches(_ probe: Probe, physical: [String], table: [IPAddressRange]) -> Bool {
        guard uid == nil, icmpType == nil, label != "wgex-resolver" else { return false }
        if let direction, direction != (probe.out ? .outbound : .inbound) {
            return false
        }
        if let interface, interface.name != "en0" {
            return false
        }
        if let family, family != .ipv4 {
            return false
        }
        if let proto, proto != probe.proto {
            return false
        }
        return Self.port(sourcePort, sourcePortEnd, probe.sourcePort) && Self.port(destinationPort, destinationPortEnd, probe.port)
            && Self.address(source, probe.source, physical, table) && Self.address(destination, probe.destination, physical, table)
    }

    private static func port(_ lower: UInt16?, _ upper: UInt16?, _ value: UInt16) -> Bool {
        guard let lower else { return true }
        return (lower ... (upper ?? lower)).contains(value)
    }

    private static func address(_ address: Address, _ host: String, _ physical: [String], _ table: [IPAddressRange]) -> Bool {
        guard let target = try? IPAddressRange(host) else { return false }
        switch address {
        case .any: return true
        case let .interfaceAddress(interface): return interface.name == "en0" && physical.contains(host)
        case .interfaceNetwork: return false
        case let .literal(text):
            if text.hasPrefix("<") {
                return table.contains { $0.contains(target) }
            }
            return (try? IPAddressRange(text))?.contains(target) == true
        }
    }
}
