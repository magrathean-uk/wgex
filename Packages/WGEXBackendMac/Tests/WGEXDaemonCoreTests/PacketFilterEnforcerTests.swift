// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct PacketFilterEnforcerTests {
    @Test
    func `state kills occur on blocking entry and underlay replacement only`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        try await enforcer.apply(.connecting(resolvers: [], endpoints: []))
        try await enforcer.apply(.connected(interfaceName: "utun7", endpoints: []))
        try await enforcer.apply(.error)
        try await enforcer.apply(.lockdown)
        #expect(await system.calls.filter { $0.contains("states") }.count == 1)
        try await enforcer.setModifiers(.init(
            allowLAN: false, captiveWindow: nil, consoleUID: 501,
            underlay: .init(v4: 8, v6: nil, resolvers: [], interfaceNames: ["en1"]),
        ))
        try await enforcer.apply(.error)
        #expect(await system.calls.filter { $0.contains("states") }.count == 2)
        try await enforcer.setModifiers(.init(
            allowLAN: false, captiveWindow: nil, consoleUID: 501,
            underlay: .init(v4: 9, v6: nil, resolvers: [], interfaceNames: ["en1"]),
        ))
        try await enforcer.apply(.error)
        #expect(await system.calls.filter { $0.contains("states") }.count == 3)
    }

    @Test
    func `stale interface names without primary indices still use global infrastructure passes`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        try await enforcer.setModifiers(.init(
            allowLAN: false,
            captiveWindow: nil,
            consoleUID: 501,
            underlay: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: ["stale0"]),
        ))
        try await enforcer.apply(.error)
        let text = await system.loaded
        #expect(text.contains("pass out quick inet proto udp from any port 68"))
        #expect(text.contains("on lo0 inet proto udp from any to 127.0.0.2 port 9"))
        #expect(!text.contains("on stale0"))
    }

    @Test
    func `error readback withdraws captive passes even with stale modifiers`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        let window = try CaptiveWindowModel.open(seconds: 60, maximum: 300, continuous: .zero, wall: Date())
        try await enforcer.setModifiers(.init(
            allowLAN: false, captiveWindow: window, consoleUID: 501,
            underlay: .init(v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"]),
        ))
        try await enforcer.apply(.captiveWindow(expires: window.expiresAtWall))
        #expect(await system.loaded.contains("port 80 user 501"))
        try await enforcer.apply(.error)
        let text = await system.loaded
        #expect(!text.contains("port 80 "))
        #expect(!text.contains("port 443 "))
        await system.setCanary(1)
        _ = try await enforcer.verifyCanary(after: 0)
        #expect(await enforcer.verificationStatus == .blocked)
    }

    @Test
    func `IPv6 only underlay renders the same family selected by the sender`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        let underlay = UnderlaySnapshot(
            v4: nil,
            v6: 6,
            resolvers: [],
            interfaceNames: ["en6"],
            interfaceV4Name: "stale4",
            interfaceV6Name: "en6",
        )
        #expect(PFCanaryFamily.choose(underlay) == .ipv6)
        try await enforcer.setModifiers(.init(allowLAN: false, captiveWindow: nil, consoleUID: 501, underlay: underlay))
        try await enforcer.apply(.error)
        #expect(await system.loaded.contains("on en6 inet6 proto udp from any to 2001:db8::1 port 9"))
        await system.setCanary(1)
        _ = try await enforcer.verifyCanary(after: 0)
        #expect(await enforcer.verificationStatus == .blocked)
    }

    @Test
    func `pfctl timeout releases the operation latch and a retry succeeds`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        await system.timeOutNextLoad()
        await #expect(throws: DaemonFailure.portTimedOut) { try await enforcer.apply(.error) }
        #expect(await enforcer.verificationStatus == .unknown)
        try await enforcer.apply(.error)
        await system.setCanary(1)
        _ = try await enforcer.verifyCanary(after: 0)
        #expect(await enforcer.verificationStatus == .blocked)
    }

    @Test
    func `captive to error readback matches the established blocking golden`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let context = try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820"), PFEndpoint("[2001:db8::8]:51820")],
            resolvers: [PFAddress("192.168.20.1"), PFAddress("2001:db8:20::1")],
            tunnelDNS: [PFAddress("10.77.0.1")], lanTunnelDNS: [PFAddress("192.168.20.53")],
            lanSubnets: [IPAddressRange("192.168.20.0/24"), IPAddressRange("2001:db8:20::/64")],
            tunnelRanges: [IPAddressRange("0.0.0.0/0"), IPAddressRange("::/0"), IPAddressRange("10.77.0.0/24")], consoleUID: 501,
        )
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: context,
            modifiers: PFModifiers(captiveWindow: true),
        )
        try await enforcer.apply(.captiveWindow(expires: Date().addingTimeInterval(60)))
        try await enforcer.apply(.error)
        let text = await system.loaded
        #expect(try text == NetworkPortHarness.fixture("PacketFilterGoldens/error-lan0-captive0.pf"))
        await system.setCanary(1)
        _ = try await enforcer.verifyCanary(after: 0)
        #expect(await enforcer.verificationStatus == .blocked)
    }

    private func make(journal: PFMemoryJournal, system: PFScriptedSystem) throws -> PolicyEnforcer {
        try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
        )
    }

    @Test
    func `profile configuration crosses the liveness adapter and renders tunnel ranges`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: system)
        let adapter = PolicyLivenessAdapter(policy: enforcer, runner: PFCtl(system: system))
        var profile = try ControllerHarness.makeProfile()
        profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
        try profile.peers[0].allowedIPs.append(IPAddressRange("10.77.0.0/24"))
        try await adapter.configureProfile(profile)
        try await adapter.setModifiers(.init(
            allowLAN: false,
            captiveWindow: nil,
            consoleUID: 501,
            underlay: .init(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"]),
        ))
        try await adapter.apply(.error)
        let rendered = await system.loaded
        #expect(!rendered.contains("10.77.0.2/24"))
        #expect(rendered.components(separatedBy: "10.77.0.0/24").count == 2)
        #expect(await system.loaded.contains("10.77.0.1/32"))
        #expect(await system.loaded.contains("block drop out quick on en0 inet6 all"))
    }

    @Test
    func `token is durable before first load and released only after empty readback`() async throws {
        let journal = PFMemoryJournal()
        let recording = PFScriptedSystem(journal: journal)
        let enforcer = try make(journal: journal, system: recording)
        try await enforcer.apply(.connecting(resolvers: ["192.0.2.53"], endpoints: ["198.51.100.1:51820"]))
        #expect(await recording.journalWasWrittenBeforeLoad)
        #expect(await enforcer.verificationStatus == .rulesVerified)
        try await enforcer.apply(.lockdown)
        let calls = await recording.calls
        #expect(calls.filter { $0 == ["-E"] }.count == 1)
        try await enforcer.apply(.disconnected)
        #expect(journal.readToken() == nil)
        #expect(await enforcer.verificationStatus == .unprotected)
        #expect(await recording.calls.last == ["-X", "99"])
        #expect(await enforcer.current() == .disconnected)
    }

    @Test(arguments: [false, true])
    func `readback mismatch or missing stock anchor reports unknown`(stock: Bool) async throws {
        let journal = PFMemoryJournal(), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: recording)
        if stock {
            await recording.setMissingStock()
        } else {
            await recording.setMismatch()
        }
        await #expect(throws: (any Error).self) { try await enforcer.apply(.lockdown) }
        #expect(await enforcer.verificationStatus == .unknown)
        #expect(await enforcer.current() == (stock ? .error : .disconnected))
        if stock {
            #expect(await enforcer.siblingAnchors.contains("com.apple/200.AirDrop"))
        }
        await #expect(throws: DaemonFailure.pfVerification) { try await enforcer.verifyCanary(after: 0) }
    }

    @Test
    func `journal failure prevents enable and leaves the blocking replacement loaded`() async throws {
        let journal = PFMemoryJournal(failWrite: true), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: recording)
        await #expect(throws: (any Error).self) { try await enforcer.apply(.lockdown) }
        let calls = await recording.calls
        #expect(!calls.contains(["-E"]))
        #expect(!calls.contains(["-X", "99"]))
        #expect(calls.contains { $0.contains("-f") })
        #expect(await enforcer.verificationStatus == .unknown)
    }

    @Test
    func `canary must increment and rules must still match`() async throws {
        let journal = PFMemoryJournal(), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: recording)
        try await enforcer.apply(.connected(interfaceName: "utun7", endpoints: []))
        await recording.setCanary(5)
        #expect(try await enforcer.verifyCanary(after: 4) == 5)
        #expect(await enforcer.verificationStatus == .protected)
        await #expect(throws: DaemonFailure.pfVerification) { try await enforcer.verifyCanary(after: 5) }
        #expect(await enforcer.verificationStatus == .unknown)
        await recording.setMismatch()
        await #expect(throws: DaemonFailure.pfVerification) { try await enforcer.verifyCanary(after: 0) }
    }

    @Test
    func `captive and teardown do not kill states`() async throws {
        let journal = PFMemoryJournal(), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal: journal, system: recording)
        try await enforcer.apply(.captiveWindow(expires: Date().addingTimeInterval(60)))
        try await enforcer.apply(.disconnecting)
        #expect(await !recording.calls.contains { $0.contains("states") })
        await #expect(throws: (any Error).self) { try await enforcer.apply(.captiveWindow(expires: .distantPast)) }
    }
}

private struct PacketFilterLifecycleTests {
    private func make(_ journal: PFMemoryJournal, _ recording: PFScriptedSystem) throws -> PolicyEnforcer {
        try PolicyEnforcer(
            runner: PFCtl(system: recording),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
        )
    }

    @Test
    func `restored token never enables a second reference`() async throws {
        let journal = PFMemoryJournal(token: "99")
        let recording = PFScriptedSystem(journal: journal)
        let enforcer = try make(journal, recording)
        try await enforcer.apply(.lockdown)
        #expect(await !recording.calls.contains(["-E"]))
        #expect(journal.readToken() == "99")
    }

    @Test
    func `disabled PF invalidates an otherwise incrementing canary`() async throws {
        let journal = PFMemoryJournal(), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal, recording)
        try await enforcer.apply(.lockdown)
        await recording.setCanary(9)
        await recording.setDisabled()
        await #expect(throws: DaemonFailure.pfVerification) { try await enforcer.verifyCanary(after: 8) }
        #expect(await enforcer.verificationStatus == .unknown)
    }

    @Test
    func `release failure preserves the token and reports unknown`() async throws {
        let journal = PFMemoryJournal(), recording = PFScriptedSystem(journal: PFMemoryJournal())
        let enforcer = try make(journal, recording)
        try await enforcer.apply(.lockdown)
        await recording.setFailRelease()
        await #expect(throws: DaemonFailure.portSystem(code: 3)) { try await enforcer.apply(.disconnected) }
        #expect(journal.readToken() == "99")
        #expect(await enforcer.current() == .lockdown)
        #expect(await enforcer.verificationStatus == .unknown)
    }
}
