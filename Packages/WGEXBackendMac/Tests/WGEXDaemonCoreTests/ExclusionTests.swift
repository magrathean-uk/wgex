// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// DEC-087 tunnel exclusions on the Mac: packet-filter rules, the carved route plan and host-name resolution. Rules and
/// routes are only rendered and planned here, never applied.
@Suite(.timeLimit(.minutes(1)))
private struct ExclusionTests {
    private static let excluded = try? [IPAddressRange("192.0.2.0/24"), IPAddressRange("2001:db8:5::/48")]

    private static func context() throws -> PFContext {
        try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820"), PFEndpoint("[2001:db8::8]:51820")],
            resolvers: [PFAddress("192.168.20.1")], tunnelDNS: [PFAddress("10.77.0.1")],
            lanSubnets: [IPAddressRange("192.168.20.0/24")],
            tunnelRanges: [
                IPAddressRange("0.0.0.0/0"),
                IPAddressRange("::/0"),
                IPAddressRange("10.77.0.0/24"),
                IPAddressRange("192.0.0.0/8"),
            ],
            consoleUID: 501,
        )
    }

    private static let exclusionLines = [
        "pass out quick on en0 inet from any to 192.0.2.0/24 no state",
        "pass in quick on en0 inet from 192.0.2.0/24 to any no state",
        "pass out quick on en0 inet6 from any to 2001:db8:5::/48 no state",
        "pass in quick on en0 inet6 from 2001:db8:5::/48 to any no state",
    ]

    @Test(arguments: [PFPhase.connecting, .connected, .error, .lockdown])
    func `exclusions add passes on the physical interface after the DNS blocks and before the tunnel ranges`(phase: PFPhase) throws {
        let without = try PacketFilterRenderer.render(phase: phase, modifiers: PFModifiers(), context: Self.context())
            .split(separator: "\n").map(String.init)
        let with = try PacketFilterRenderer.render(
            phase: phase, modifiers: PFModifiers(exclusions: #require(Self.excluded)), context: Self.context(),
        ).split(separator: "\n").map(String.init)
        // Snapshot: the same policy with exactly these four lines inserted before the first PMTU or tunnel-range rule.
        let insertion = try #require(without.firstIndex { line in
            line.contains("icmp-type 3") || line.contains("icmp6-type 2") || (line.hasPrefix("block") && line.contains("<wgex_"))
        })
        #expect(with == Array(without[..<insertion]) + Self.exclusionLines + Array(without[insertion...]))
        let dnsBlock = try #require(with.firstIndex { $0.hasSuffix("port 853") || $0.contains("port 853 ") })
        let table = try #require(with.firstIndex { $0.hasPrefix("block") && $0.contains("to <wgex_") })
        let first = try #require(with.firstIndex(of: Self.exclusionLines[0]))
        #expect(dnsBlock < first && first < table)
        #expect(with.last == "block drop quick all")
    }

    @Test
    func `no exclusion rule without enforcement, on a loopback canary or for a default route`() throws {
        let modifiers = try PFModifiers(exclusions: #require(Self.excluded) + [IPAddressRange("0.0.0.0/0")])
        #expect(modifiers.exclusions == Self.excluded)
        #expect(try PacketFilterRenderer.render(phase: .disconnected, modifiers: modifiers, context: Self.context()).isEmpty)
        let loopback = try PFModifiers(canary: .loopback, exclusions: #require(Self.excluded))
        let text = try PacketFilterRenderer.render(phase: .error, modifiers: loopback, context: Self.context())
        #expect(!text.contains("192.0.2.0/24"))
    }

    @Test
    func `IPv6 exclusions follow a separate IPv6 underlay`() throws {
        let modifiers = try PFModifiers(ipv6Underlay: PFInterface("en1"), exclusions: #require(Self.excluded))
        let text = try PacketFilterRenderer.render(phase: .connected, modifiers: modifiers, context: Self.context())
        #expect(text.contains("pass out quick on en0 inet from any to 192.0.2.0/24 no state\n"))
        #expect(text.contains("pass out quick on en1 inet6 from any to 2001:db8:5::/48 no state\n"))
        #expect(text.contains("pass in quick on en1 inet6 from 2001:db8:5::/48 to any no state\n"))
        #expect(!text.contains("on en0 inet6 from any to 2001:db8:5::/48"))
    }

    /// M08-R01 F1, render-level first match: an excluded range that contains the physical address must not let that
    /// address send from an unlisted local port to a destination outside the exclusions. IPv4 and IPv6, on one underlay
    /// and on split underlays (IPv6 on en1), in every enforcing phase.
    @Test(arguments: [PFPhase.connecting, .connected, .error, .lockdown], [false, true])
    func `an exclusion containing the physical address passes only traffic to and from the excluded range`(
        phase: PFPhase, split: Bool,
    ) throws {
        let v6 = split ? "en1" : "en0"
        let context = try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820")],
            resolvers: [PFAddress("192.168.20.1")], tunnelDNS: [PFAddress("10.77.0.1")],
            lanSubnets: [IPAddressRange("192.168.20.0/24")],
            tunnelRanges: [IPAddressRange("0.0.0.0/0"), IPAddressRange("::/0")],
            consoleUID: 501,
        )
        let modifiers = try PFModifiers(
            ipv6Underlay: split ? PFInterface("en1") : nil,
            exclusions: [IPAddressRange("192.168.20.0/24"), IPAddressRange("2001:db8:20::/64")],
        )
        let rules = try PacketFilterRenderer.rules(phase: phase, modifiers: modifiers, context: context)
        var physical = ["en0": ["192.168.20.10"]]
        physical[v6, default: []].append("2001:db8:20::10")
        func verdict(_ probe: ExclusionProbe) -> PFRule.Action? {
            rules.first { $0.admits(probe, physical: physical, lan: context.lanSubnets, table: context.tunnelRanges) }?.action
        }
        for (interface, own, excluded, outside) in [
            ("en0", "192.168.20.10", "192.168.20.30", "203.0.113.50"),
            (v6, "2001:db8:20::10", "2001:db8:20::30", "2001:db8:99::50"),
        ] {
            // The bypass the review found: own address, unlisted port, non-excluded destination.
            #expect(verdict(.init(interface, out: true, .tcp, own, 40000, outside, 443)) == .block)
            #expect(verdict(.init(interface, out: true, .udp, own, 40000, outside, 443)) == .block)
            #expect(verdict(.init(interface, out: false, .tcp, outside, 443, own, 40000)) == .block)
            // Traffic to and from the excluded range still passes.
            #expect(verdict(.init(interface, out: true, .tcp, own, 40000, excluded, 443)) == .pass)
            #expect(verdict(.init(interface, out: false, .tcp, excluded, 443, own, 40000)) == .pass)
            // DNS to an excluded address stays blocked.
            #expect(verdict(.init(interface, out: true, .udp, own, 40000, excluded, 53)) == .block)
        }
    }

    @Test
    func `the route plan carves exclusions out of a full tunnel and keeps the plan unchanged without them`() throws {
        let profile = try ControllerHarness.makeProfile()
        let plain = TunnelController.routes(profile, interfaceName: "utun7")
        #expect(plain == TunnelController.routes(profile, interfaceName: "utun7", excluding: []))
        #expect(plain.map { "\($0.destination)/\($0.prefixLength)" } == ["0.0.0.0/1", "128.0.0.0/1", "8000::/1", "::/1"])
        let carved = try TunnelController.routes(profile, interfaceName: "utun7", excluding: #require(Self.excluded))
        let ranges = try carved.map { try IPAddressRange("\($0.destination)/\($0.prefixLength)") }
        #expect(carved.allSatisfy { $0.interfaceName == "utun7" && $0.prefixLength > 0 })
        let excluded = try #require(Self.excluded)
        #expect(!ranges.contains { range in excluded.contains { range.overlaps($0) } })
        // Everything else stays in the tunnel: the carved IPv4 plan covers every other address exactly once.
        let v4 = ranges.filter { !$0.isIPv6 }
        let total = v4.reduce(UInt64(0)) { $0 + (UInt64(1) << (32 - $1.prefixLength)) }
        #expect(total == (UInt64(1) << 32) - 256)
        #expect(v4.count == 24)
        #expect(ranges.filter(\.isIPv6).count == 48)
    }

    @Test
    func `resolution state drops tunnel addresses, reports failures and falls back to literals over the route limit`() throws {
        var profile = try ControllerHarness.makeProfile()
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "a.example.test", "b.example.test", "c.example.test"])
        let state = try TunnelController.exclusionState(profile, found: [
            "a.example.test": [IPAddressRange("203.0.113.5")],
            "b.example.test": [IPAddressRange("10.77.0.1")],
        ])
        #expect(state.profileID == profile.id)
        #expect(try state.ranges == [IPAddressRange("198.51.100.0/24"), IPAddressRange("203.0.113.5")])
        #expect(state.unresolved == ["b.example.test", "c.example.test"])

        // Hosts spread across separate IPv6 subtrees so carving around them needs over 4096 routes.
        let many = try (0 ..< 64).map { try IPAddressRange("\(String(0x2000 + $0 * 0x40, radix: 16))::1") }
        let crowded = TunnelController.exclusionState(profile, found: ["a.example.test": many])
        #expect(try crowded.ranges == [IPAddressRange("198.51.100.0/24")])
        #expect(crowded.unresolved == profile.exclusions.hostNames)
    }

    @Test
    func `a start resolves excluded names, carves the routes and passes the addresses to the policy`() async throws {
        let harness = try ControllerHarness()
        var profile = try ControllerHarness.makeProfile()
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "excluded.example.test"])
        try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        let epoch = try await harness.controller.start(
            profileID: profile.id, connectionUID: ControllerHarness.uid, secrets: ControllerHarness.bundle(),
        )
        let expected = try [IPAddressRange("192.0.2.1"), IPAddressRange("198.51.100.0/24"), IPAddressRange("2001:db8::1")]
        #expect(await harness.ports.modifiers.last?.exclusions == expected)
        let routes = try await #require(harness.ports.routeItems[epoch])
            .map { try IPAddressRange("\($0.destination)/\($0.prefixLength)") }
        #expect(!routes.contains { route in expected.contains { route.overlaps($0) } })
        #expect(await harness.controller.status.unresolvedExclusions.isEmpty)

        // A network change that moves the name re-carves the routes: new ones first, then the stale ones go.
        await harness.ports.setAnswers(["192.0.2.9"])
        try await harness.controller.refreshEndpoints(generation: epoch)
        let moved = try await #require(harness.ports.routeItems[epoch])
            .map { try IPAddressRange("\($0.destination)/\($0.prefixLength)") }
        let restored = try IPAddressRange("192.0.2.1"), moving = try IPAddressRange("192.0.2.9")
        #expect(moved.contains { $0.contains(restored) })
        #expect(!moved.contains { $0.overlaps(moving) })
        #expect(harness.trace.calls.contains("routes.removeSome"))
        let journalled = harness.journal.snapshot().resources.first { $0.generation == epoch }?.routes ?? []
        let installed = await harness.ports.routeItems[epoch] ?? []
        #expect(Set(journalled) == Set(installed))
    }

    @Test
    func `a name that resolves only to the tunnel's own addresses warns and never blocks the start`() async throws {
        let harness = try ControllerHarness()
        await harness.ports.setAnswers(["10.77.0.1"])
        var profile = try ControllerHarness.makeProfile()
        profile.exclusions = try TunnelExclusions(entries: ["dns.example.test"])
        try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        _ = try await harness.controller.start(
            profileID: profile.id,
            connectionUID: ControllerHarness.uid,
            secrets: ControllerHarness.bundle(),
        )
        #expect(await harness.controller.status.unresolvedExclusions == ["dns.example.test"])
        #expect(await harness.ports.modifiers.last?.exclusions == [])
    }
}

/// One TCP or UDP packet on a named interface for the first-match check.
private struct ExclusionProbe {
    let interface: String
    let out: Bool
    let proto: PFRule.ProtocolName
    let source: String
    let sourcePort: UInt16
    let destination: String
    let port: UInt16

    init(
        _ interface: String, out: Bool, _ proto: PFRule.ProtocolName,
        _ source: String, _ sourcePort: UInt16, _ destination: String, _ port: UInt16,
    ) {
        self.interface = interface; self.out = out; self.proto = proto
        self.source = source; self.sourcePort = sourcePort; self.destination = destination; self.port = port
    }
}

private extension PFRule {
    /// A conservative matcher: user, group and route-to selectors are treated as matching any packet, so a pass that
    /// could apply is never missed; ICMP-type rules never match a TCP or UDP probe.
    func admits(_ probe: ExclusionProbe, physical: [String: [String]], lan: [IPAddressRange], table: [IPAddressRange]) -> Bool {
        guard icmpType == nil else { return false }
        if let direction, direction != (probe.out ? .outbound : .inbound) {
            return false
        }
        if let interface, interface.name != probe.interface {
            return false
        }
        if let family, family != (probe.source.contains(":") ? .ipv6 : .ipv4) {
            return false
        }
        if let proto, proto != probe.proto {
            return false
        }
        func port(_ lower: UInt16?, _ upper: UInt16?, _ value: UInt16) -> Bool {
            guard let lower else { return true }
            return (lower ... (upper ?? lower)).contains(value)
        }
        func address(_ address: Address, _ host: String) -> Bool {
            guard let target = try? IPAddressRange(host) else { return false }
            switch address {
            case .any: return true
            case let .interfaceAddress(interface):
                return interface.name == probe.interface && physical[interface.name, default: []].contains(host)
            case let .interfaceNetwork(interface):
                return interface.name == probe.interface && lan.contains { $0.contains(target) }
            case let .literal(text):
                if text.hasPrefix("<") {
                    return table.contains { $0.contains(target) }
                }
                return (try? IPAddressRange(text))?.contains(target) == true
            }
        }
        return port(sourcePort, sourcePortEnd, probe.sourcePort) && port(destinationPort, destinationPortEnd, probe.port)
            && address(source, probe.source) && address(destination, probe.destination)
    }
}
