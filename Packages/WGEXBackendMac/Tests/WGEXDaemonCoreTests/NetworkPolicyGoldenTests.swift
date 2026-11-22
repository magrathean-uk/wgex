// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore

private struct NetworkPolicyGoldenTests {
    private static func context() throws -> PFContext {
        try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820"), PFEndpoint("[2001:db8::8]:51820")],
            resolvers: [PFAddress("192.168.20.1"), PFAddress("2001:db8:20::1")],
            tunnelDNS: [PFAddress("10.77.0.1")], lanTunnelDNS: [PFAddress("192.168.20.53")],
            lanSubnets: [IPAddressRange("192.168.20.0/24"), IPAddressRange("2001:db8:20::/64")],
            tunnelRanges: [IPAddressRange("0.0.0.0/0"), IPAddressRange("::/0"), IPAddressRange("10.77.0.0/24")], consoleUID: 501,
        )
    }

    @Test(arguments: [IPv6Policy.tunnel, .blockOutside, .allowOutside])
    func `IPv6 routes and pf consequences are golden`(policy: IPv6Policy) throws {
        var profile = try ControllerHarness.makeProfile()
        profile.protection.ipv6Policy = policy
        if policy == .tunnel {
            try profile.peers[0].allowedIPs.append(IPAddressRange("::/0"))
        }
        let routes = TunnelController.routes(profile, interfaceName: "utun7")
            .map { "\($0.destination)/\($0.prefixLength) \($0.interfaceName)\n" }.joined()
        #expect(try routes == (NetworkPortHarness.fixture("NetworkPolicyGoldens/\(policy.rawValue).routes")))
        let pf = try PacketFilterRenderer.render(phase: .connected, modifiers: PFModifiers(ipv6Policy: policy), context: Self.context())
        #expect(try pf == (NetworkPortHarness.fixture("NetworkPolicyGoldens/\(policy.rawValue).pf")))
        #expect(pf.split(separator: "\n").last == "block drop quick all")
        if policy == .allowOutside {
            let dns = try #require(pf.range(of: "port 853")), pass = try #require(pf.range(of: "on en0 inet6 all keep state"))
            #expect(dns.lowerBound < pass.lowerBound)
        }
    }

    @Test
    func `Apple route to is enabled only for an explicitly approved OS build and connected policy`() throws {
        let context = try Self.context(), tunnel = try PFInterface("utun7")
        #expect(try AppleServiceRouteTo(
            osBuild: "unverified",
            approvedBuilds: [],
            tunnel: tunnel,
            destinations: [IPAddressRange("17.0.0.0/8")],
        ) == nil)
        let modifier = try #require(AppleServiceRouteTo(
            osBuild: "synthetic-lab-build", approvedBuilds: ["synthetic-lab-build"], tunnel: tunnel,
            destinations: [IPAddressRange("17.0.0.0/8")],
        ))
        let pf = try PacketFilterRenderer.render(phase: .connected, modifiers: PFModifiers(appleServices: modifier), context: context)
        #expect(try pf == (NetworkPortHarness.fixture("NetworkPolicyGoldens/apple.pf")))
        for phase in [PFPhase.connecting, .error, .lockdown] {
            #expect(try !PacketFilterRenderer.render(phase: phase, modifiers: PFModifiers(appleServices: modifier), context: context)
                .contains("route-to"))
        }
        #expect(try !PacketFilterRenderer.render(
            phase: .connected,
            modifiers: PFModifiers(captiveWindow: true, appleServices: modifier),
            context: context,
        ).contains("route-to"))
    }

    @Test
    func `IPv6 primary on a second underlay has its own rules and narrow captive passes`() throws {
        let modifiers = try PFModifiers(ipv6Underlay: PFInterface("en1"))
        let text = try PacketFilterRenderer.render(phase: .connected, modifiers: modifiers, context: Self.context())
        #expect(try text == (NetworkPortHarness.fixture("NetworkPolicyGoldens/dual-underlay.pf")))
        let captive = try PacketFilterRenderer.render(
            phase: .connected, modifiers: PFModifiers(captiveWindow: true, ipv6Underlay: PFInterface("en1")), context: Self.context(),
        )
        #expect(captive.contains("on en0 inet proto tcp from any to any port 443 user 501"))
        #expect(captive.contains("on en1 inet6 proto tcp from any to any port 443 user 501"))
    }
}
