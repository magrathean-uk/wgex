// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct VerifierPFTests {
    @Test(arguments: [false, true])
    func `connecting DNS goldens never mention a tunnel device`(overlapsTunnel: Bool) async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
        )
        var profile = try ControllerHarness.makeProfile()
        profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
        profile.peers[0].allowedIPs = try [IPAddressRange("10.77.0.0/24")]
        profile.protection.ipv6Policy = .tunnel
        let dns = overlapsTunnel ? "10.77.0.1" : "192.168.20.53"
        profile.interface.dns = try [DNSServer(dns)]
        try await enforcer.configureProfile(profile)
        try await enforcer.setModifiers(.init(allowLAN: true, captiveWindow: nil, consoleUID: 501, underlay: .init(
            v4: 4, v6: 6, resolvers: ["192.168.20.1"], interfaceNames: ["en0"],
            lanSubnets: [IPAddressRange("10.77.0.0/24"), IPAddressRange("192.168.20.0/24")], ipv6DefaultRouteAvailable: false,
        )))
        try await enforcer.apply(.connecting(resolvers: ["192.168.20.1"], endpoints: ["198.51.100.8:51820"]))
        let connecting = await system.loaded
        #expect(await system.calls.filter { $0.contains("-T") }.count == 1)
        #expect(!connecting.contains("utun"))
        #expect(!connecting.contains("block drop out quick on en0 inet6 all"))
        #expect(!connecting.contains("to \(dns) port 53"))
        let name = overlapsTunnel ? "tunnel.pf" : "lan.pf"
        if let root = ProcessInfo.processInfo.environment["CLEAN_DEV_BUILDS"] {
            try connecting.write(
                to: URL(fileURLWithPath: root).appendingPathComponent("M1-05-connecting-" + name),
                atomically: true,
                encoding: .utf8,
            )
        }
        #expect(try connecting == NetworkPortHarness.fixture("ConnectingDNS/" + name))
        try await enforcer.apply(.connected(interfaceName: "utun7", endpoints: []))
        let connected = await system.loaded
        #expect(await system.calls.filter { $0.contains("-T") }.count == 2)
        #expect(connected.contains("on \(overlapsTunnel ? "utun7" : "en0") inet proto udp from any to \(dns) port 53"))
        if overlapsTunnel {
            #expect(!connected.contains("on en0 inet proto udp from any to \(dns) port 53"))
        }
    }

    @Test
    func `an endpoint connecting load failure is a policy verification failure`() async throws {
        let system = PFScriptedSystem(journal: PFMemoryJournal())
        await system.failEndpointLoad()
        let h = try ControllerHarness(policyFactory: { journal in
            try PolicyEnforcer(
                runner: PFCtl(system: system),
                journal: DaemonPFTokenJournal(journal: journal),
                context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
                canaryProbe: { await system.probe() },
            )
        }, underlay: .init(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"]))
        try await h.install()
        await #expect(throws: DaemonFailure.controllerPolicyVerificationFailed) { _ = try await h.start() }
    }

    @Test
    func `a mismatched tunnel range table prevents a protection claim`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        await system.setTableMismatch()
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(
                underlay: PFInterface("en0"),
                tunnelRanges: [IPAddressRange("10.77.0.0/24")],
                consoleUID: 501,
            ),
        )
        await #expect(throws: (any Error).self) { try await enforcer.apply(.lockdown) }
        #expect(await enforcer.verification() == .unknown)
    }

    @Test
    func `a second enable holder cannot hide loss of our reference past six checks`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        try await enforcer.apply(.lockdown)
        await system.releaseOwnedReference()
        for _ in 0 ..< 5 {
            try await enforcer.verifyEvaluation()
        }
        let before = await system.calls.count
        await #expect(throws: (any Error).self) { try await enforcer.verifyEvaluation() }
        #expect(await system.calls.count - before <= 2)
        #expect(journal.readToken() == nil)
        #expect(await enforcer.verification() == .unknown)
        #expect(await !system.calls.contains(["-X", "12345"]))
    }
}

#if WGEX_LAB_BUILD
    private struct VerifierPFDiagnosticsTests {
        @Test
        func `PF failure diagnostics retain only bounded allowlisted stderr`() {
            let line = "pfctl: DIOCADDRULE: Device not configured"
            #expect(DaemonDiagnostics.packetFilterStderr(line) == line)
            #expect(DaemonDiagnostics.packetFilterStderr("stdin:12: syntax error") == "stdin:12: syntax error")
            #expect(DaemonDiagnostics.packetFilterStderr("unlisted-payload") == "")
            #expect(DaemonDiagnostics.packetFilterStderr("pfctl: DIOCADDRULE private_key=withheld-payload") == "")
            #expect(DaemonDiagnostics.packetFilterStderr(Array(repeating: line, count: 100).joined(separator: "\n")).utf8.count <= 512)
            #expect(DaemonDiagnostics.packetFilterArguments(["-X", "12345"]) == "-X <withheld>")
        }
    }
#endif
