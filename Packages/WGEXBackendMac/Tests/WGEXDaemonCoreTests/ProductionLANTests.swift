// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore

private struct ProductionLANTests {
    @Test(arguments: PFPhase.allCases, [false, true])
    func `production modifiers generate the LAN and captive goldens`(phase: PFPhase, allowLAN: Bool) async throws {
        for captive in [false, true] {
            let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
            let enforcer = try PolicyEnforcer(
                runner: PFCtl(system: system),
                journal: journal,
                context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            )
            var profile = try ControllerHarness.makeProfile()
            profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
            profile.peers[0].allowedIPs = try [IPAddressRange("10.77.0.0/24")]
            profile.interface.dns = try [DNSServer("10.77.0.1"), DNSServer("192.168.20.53")]
            profile.protection.ipv6Policy = .tunnel
            let subnets = UnderlayMonitorModel.lanSubnets(
                addresses: ["192.168.20.8"], masks: ["255.255.255.0"],
                addressesV6: ["2001:db8:20::8"], prefixes: [64],
            )
            let underlay = UnderlayMonitorModel.snapshot(
                ipv4: ["PrimaryInterface": "en0"], ipv6: ["PrimaryInterface": "en0", "Router": "2001:db8:20::1"], indexes: ["en0": 4],
                resolvers: ["192.168.20.1", "2001:db8:20::1"], lanSubnets: subnets,
            )
            try await enforcer.configureProfile(profile)
            let window = try CaptiveWindowModel.open(seconds: 600, maximum: 600, continuous: .zero, wall: Date())
            try await enforcer.setModifiers(.init(
                allowLAN: allowLAN,
                captiveWindow: captive ? window : nil,
                consoleUID: 501,
                underlay: underlay,
            ))
            let endpoints = ["198.51.100.8:51820", "[2001:db8::8]:51820"]
            let policy: PacketFilterPolicy = if captive {
                .captiveWindow(expires: window.expiresAtWall)
            } else {
                switch phase {
                case .disconnected: .disconnected
                case .connecting: .connecting(resolvers: underlay.resolvers, endpoints: endpoints)
                case .connected: .connected(interfaceName: "utun7", endpoints: endpoints)
                case .disconnecting: .disconnecting
                case .error: .error
                case .lockdown: .lockdown
                }
            }
            try await enforcer.apply(policy)
            let name = "\(phase.rawValue)-lan\(allowLAN ? 1 : 0)-captive\(captive ? 1 : 0).pf"
            let text = await system.loaded
            #expect(try text == NetworkPortHarness.fixture("ProductionModifiers/" + name))
            try capture(text, name: name)
        }
    }

    @Test
    func `invalid primary masks never produce a broad LAN exemption`() {
        let subnets = UnderlayMonitorModel.lanSubnets(
            addresses: ["192.0.2.8", "198.51.100.8", "203.0.113.8"], masks: ["0.0.0.0", "255.0.255.0", "255.255.255.0"],
            addressesV6: ["2001:db8::8", "2001:db8:1::8"], prefixes: [0, 129],
        )
        #expect(subnets.map(\.stringRepresentation) == ["203.0.113.0/24"])
    }

    private func capture(_ text: String, name: String) throws {
        guard let root = ProcessInfo.processInfo.environment["CLEAN_DEV_BUILDS"] else { return }
        #if WGEX_LAB_BUILD
            let variant = "lab"
        #else
            let variant = "plain"
        #endif
        let directory = URL(fileURLWithPath: root).appendingPathComponent("M1-05-production-goldens-" + variant)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try text.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }
}
