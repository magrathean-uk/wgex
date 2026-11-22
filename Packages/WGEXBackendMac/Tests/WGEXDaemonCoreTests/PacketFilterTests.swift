// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct PacketFilterTests {
    @Test
    func `verbose rules provide canonical rule text and counters together`() {
        let rendered = "block drop out quick proto udp from any to 192.0.2.1 port 9 label \"wgex-canary\"\nblock drop quick all\n"
        let verbose = "@0 block drop out quick proto udp from any to 192.0.2.1 port = 9 label \"wgex-canary\"\n  [ Evaluations: 8 Packets: 0 Bytes: 0 States: 0 ]\n  [ Inserted: uid 0 pid 123 ]\n@1 block drop quick all\n  [ Evaluations: 0 Packets: 0 Bytes: 0 States: 0 ]\n"
        #expect(PacketFilterReadback.matches(verbose, rendered: rendered))
        #expect(!PacketFilterReadback.matches(verbose + "unexpected kernel output", rendered: rendered))
    }

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

    #if WGEX_LAB_BUILD
        @Test(arguments: [PFPhase.connecting, .connected, .error, .lockdown])
        func `lab escape hatch passes host SSH ahead of every block`(phase: PFPhase) throws {
            var context = try PFContext(
                underlay: PFInterface("en0"), tunnel: PFInterface("utun7"), consoleUID: 501,
            )
            context.labEscapeHatch = try PFAddress("192.168.64.1")
            let text = try PacketFilterRenderer.render(phase: phase, modifiers: PFModifiers(), context: context)
            let lines = text.split(separator: "\n").map(String.init)
            #expect(lines.first == "pass in quick on en0 inet proto tcp from 192.168.64.1 to any port 22 no state")
            #expect(lines.dropFirst()
                .first == "pass out quick on en0 inet proto tcp from any port 22 to 192.168.64.1 no state")
            let plain = try PacketFilterRenderer.render(
                phase: phase, modifiers: PFModifiers(),
                context: PFContext(underlay: PFInterface("en0"), tunnel: PFInterface("utun7"), consoleUID: 501),
            )
            #expect(!plain.contains("192.168.64.1"))
        }

    #endif

    @Test(arguments: PFPhase.allCases, [false, true])
    func `RT-21 every policy and modifier golden`(phase: PFPhase, allowLAN: Bool) throws {
        for captive in [false, true] {
            let text = try PacketFilterRenderer.render(
                phase: phase,
                modifiers: PFModifiers(allowLAN: allowLAN, captiveWindow: captive),
                context: Self.context(),
            )
            let name = "\(phase.rawValue)-lan\(allowLAN ? 1 : 0)-captive\(captive ? 1 : 0).pf"
            let url = try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
                .appendingPathComponent("PacketFilterGoldens/\(name)")
            let expected = try Data(contentsOf: url)
            #expect(Data(text.utf8) == expected)
            let expectedLines = String(decoding: expected, as: UTF8.self).split(separator: "\n")
            if let difference = zip(text.split(separator: "\n"), expectedLines).first(where: { $0 != $1 }) {
                #expect(difference.0 == difference.1)
            }
            let lines = text.split(separator: "\n")
            #expect(!lines.contains { $0.hasPrefix("set ") })
            #expect(lines.allSatisfy { $0.contains("quick") || $0.hasPrefix("table <wgex_") })
            if !text.isEmpty {
                #expect(lines.last == "block drop quick all")
                #expect(!text.contains("icmp6-type 137"))
                #expect(text.contains("port 67 to any port 68"))
                #expect(text.contains("from fe80::/10 port 547 to fe80::/10 port 546"))
                #expect(!text.contains("to 0.0.0.0/0"))
                #expect(!text.contains("to ::/0"))
                if allowLAN {
                    let dns = try #require(lines.firstIndex { $0.hasPrefix("block drop out quick proto tcp") })
                    let lan = try #require(lines.firstIndex { $0.contains("from 192.168.20.0/24 to 192.168.20.0/24") })
                    #expect(dns < lan)
                    let tunnelBlock = try #require(lines
                        .firstIndex { $0.hasPrefix("block drop out quick on en0 inet from any to <wgex_") })
                    #expect(tunnelBlock < lan)
                }
                if captive {
                    #expect(!text.contains("on utun7")); #expect(text.contains("port 443 user 501"))
                }
            }
        }
    }

    @Test
    func `input validation prevents rule and argv injection`() throws {
        for name in ["en0\nset skip on lo0", "-a", "", "en0:network", "abcdefghijklmnop"] {
            #expect(throws: (any Error).self) { try PFInterface(name) }
        }
        for text in ["example.org:53", "1.2.3.4:0", "1.2.3.4:53\n", "::1:53"] {
            #expect(throws: (any Error).self) { try PFEndpoint(text) }
        }
        #expect(throws: (any Error).self) {
            try PFContext(underlay: PFInterface("en0"), lanSubnets: [IPAddressRange("0.0.0.0/0")], consoleUID: 501)
        }
        #expect(throws: (any Error).self) {
            try PacketFilterRenderer.render(
                phase: .connected,
                modifiers: PFModifiers(),
                context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            )
        }
    }

    @Test
    func `renderer is independent of duplicate and input ordering`() throws {
        let one = try PFContext(
            underlay: PFInterface("en0"),
            endpoints: [PFEndpoint("1.2.3.4:7"), PFEndpoint("1.2.3.5:7")],
            consoleUID: 501,
        )
        let two = try PFContext(underlay: PFInterface("en0"), endpoints: one.endpoints.reversed() + one.endpoints, consoleUID: 501)
        #expect(try PacketFilterRenderer.render(phase: .connecting, modifiers: PFModifiers(), context: one)
            == PacketFilterRenderer.render(phase: .connecting, modifiers: PFModifiers(), context: two))
    }

    @Test
    func `readback normalises only known PF spelling differences`() throws {
        #expect(PacketFilterReadback.matches(
            "@0 pass quick on lo0 from any to any no state\n",
            rendered: "pass quick on lo0 all no state\n",
        ))
        #expect(PacketFilterReadback.matches(
            "pass out quick proto udp to any port = 53 user = root keep state",
            rendered: "pass out quick proto udp to any port 53 user 0 keep state",
        ))
        #expect(!PacketFilterReadback.matches("pass quick all", rendered: "block drop quick all"))
        #expect(!PacketFilterReadback.matches("block drop all", rendered: "block drop quick all"))
        #expect(PacketFilterReadback.stockAnchorPresent("scrub-anchor \"com.apple/*\" all\nanchor \"com.apple/*\" all\n"))
        #expect(!PacketFilterReadback.stockAnchorPresent("anchor \"com.apple/*\" from 192.0.2.1 to any"))
        #expect(try PacketFilterReadback.referenceTokens(PFTranscripts.read("references-with-token")) == [PFTranscripts.capturedToken])
        #expect(try PacketFilterReadback.referenceTokens(PFTranscripts.read("references-before")).isEmpty)
        #expect(PacketFilterReadback.referenceTokens("PID: 123 Token: 99\n") == ["99"])
        #expect(!PacketFilterReadback.stockAnchorPresent("# anchor \"com.apple/*\" all"))
        #expect(!PacketFilterReadback.stockAnchorPresent("anchor \"com.apple/*\" out on en0 all"))
        #expect(try PacketFilterReadback.token("pf enabled\nToken : 18446744073709551615\n") == "18446744073709551615")
        #expect(try PacketFilterReadback
            .token("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 17076040950846840334\n")
            == "17076040950846840334")
        for value in ["Token : nope", "Token : -1", "Token : 1\nToken : 2", "Token : 18446744073709551616", ""] {
            #expect(throws: DaemonFailure.pfToken) { try PacketFilterReadback.token(value) }
        }
    }

    @Test
    func `canary reads evaluations from its own rule`() throws {
        let text = """
        @0 pass quick on lo0 all no state
          [ Evaluations: 999 Packets: 8 Bytes: 12 States: 0 ]
        @1 block drop out quick on en0 inet proto udp from any to 192.0.2.1 port = 9 user = 0 label "wgex-canary"
          [ Evaluations: 42 Packets: 1 Bytes: 5 States: 0 ]
        @2 block drop quick all
          [ Evaluations: 1000 Packets: 0 Bytes: 0 States: 0 ]
        """
        #expect(try PacketFilterReadback.canaryEvaluations(text) == 42)
        #expect(throws: DaemonFailure.pfVerification) { try PacketFilterReadback.canaryEvaluations("[ Evaluations: 4 ]") }
    }
}

@Suite(.timeLimit(.minutes(15)))
private struct PacketFilterRunnerTests {
    @Test
    func `cancelled enable child is reaped before compensation can inspect references`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        let child = Mutex<Int32>(0)
        await #expect(throws: DaemonFailure.pfJournal) {
            try await fixture.system.enable(deadline: PFFixture.processDeadline) { pid in
                child.withLock { $0 = pid }
                fixture.expectNoExecutionDuringCallback()
                throw DaemonFailure.pfJournal
            }
        }
        let pid = child.withLock { $0 }
        #expect(pid > 0)
        let result = Darwin.kill(pid, 0), code = errno
        #expect(result == -1)
        #expect(code == ESRCH)
        #expect(fixture.count == 0)
    }

    @Test
    func `enable child cannot execute until write ahead callback returns`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "stderr", PFTranscripts.read("enable", token: "42"))
        let result = try await fixture.system.enable(deadline: PFFixture.processDeadline) { pid in
            #expect(pid > 0)
            #expect(fixture.count == 0)
            fixture.expectNoExecutionDuringCallback()
            try Data("durable\n".utf8).write(to: fixture.directory.appendingPathComponent("durable"))
        }
        #expect(try fixture.recorded(1, "durable") == "durable\n")
        #expect(try PacketFilterReadback.token(result.stderr) == "42")
        #expect(fixture.count == 1)
    }

    @Test
    func `failed write ahead callback prevents enable execution`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        await #expect(throws: DaemonFailure.pfJournal) {
            try await fixture.system.enable(deadline: PFFixture.processDeadline) { _ in
                fixture.expectNoExecutionDuringCallback()
                throw DaemonFailure.pfJournal
            }
        }
        #expect(fixture.count == 0)
    }

    @Test
    func `fake records argv stdin and cleared environment`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "stdout", "reply"); try fixture.reply(1, "stderr", "warning")
        let result = try await fixture.system.run(
            arguments: ["-o", "none", "-n", "-a", "com.apple/wgex", "-f", "-"],
            input: Data("rules\n".utf8),
            deadline: PFFixture.processDeadline,
        )
        #expect(result.stdout == "reply"); #expect(result.stderr == PFTranscripts.preamble + "warning")
        #expect(try fixture.recorded(1, "argv") == "-o\nnone\n-n\n-a\ncom.apple/wgex\n-f\n-\n")
        #expect(try fixture.recorded(1, "stdin") == "rules\n")
        let environment = try fixture.recorded(1, "environment")
        #expect(!environment.contains("HOME=")); #expect(!environment.contains("PATH=")); #expect(!environment.contains("WGEX_"))
    }

    @Test
    func `both output pipes drain beyond pipe capacity`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "bulk", "1")
        let result = try await fixture.system.run(
            arguments: [],
            input: Data(repeating: 65, count: 200_000),
            deadline: PFFixture.processDeadline,
        )
        #expect(result.stdout.utf8.count == 4096 * 65); #expect(result.stderr.utf8.count == 4096 * 65 + PFTranscripts.preamble.utf8.count)
        #expect(try fixture.recorded(1, "stdin").utf8.count == 200_000)
    }

    @Test(arguments: [1, 2])
    func `nonzero dry run or load aborts remaining stages`(failure: Int) async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(failure, "status", "7\n")
        await #expect(throws: DaemonFailure.pfVerification) { try await fixture.runner.load("block drop quick all\n") }
        #expect(fixture.count == failure)
    }

    @Test
    func `load dry runs then verifies readback and mismatch fails`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        let text = "block drop quick all\n"
        try fixture.reply(3, "stdout", text)
        let runner = fixture.runner
        try await runner.load(text)
        #expect(try fixture.recorded(1, "argv") == "-o\nnone\n-n\n-a\ncom.apple/wgex\n-f\n-\n")
        #expect(try fixture.recorded(2, "argv") == "-o\nnone\n-a\ncom.apple/wgex\n-f\n-\n")
        #expect(try fixture.recorded(3, "argv") == "-a\ncom.apple/wgex\n-sr\n")
        #expect(try fixture.recorded(1, "stdin") == fixture.recorded(2, "stdin"))
        try fixture.reply(6, "stdout", "pass quick all\n")
        await #expect(throws: DaemonFailure.pfVerification) { try await runner.load(text) }
    }

    @Test
    func `token enable release references and state kill argv`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        let runner = fixture.runner
        try fixture.reply(1, "stderr", PFTranscripts.read("enable", token: "123456"))
        let token = try await runner.enable()
        try await runner.release(token: token)
        _ = try await runner.references()
        try await runner.killStates(.interface(PFInterface("en0")))
        try await runner.killStates(.hosts(interface: PFInterface("en1"), addresses: [PFAddress("192.0.2.3")]))
        #expect(try fixture.recorded(1, "argv") == "-E\n")
        #expect(try fixture.recorded(2, "argv") == "-X\n123456\n")
        #expect(try fixture.recorded(3, "argv") == "-s\nReferences\n")
        #expect(try fixture.recorded(4, "argv") == "-i\nen0\n-F\nstates\n")
        #expect(try fixture.recorded(5, "argv") == "-i\nen1\n-k\n192.0.2.3\n")
        #expect(try fixture.recorded(6, "argv") == "-i\nen1\n-k\n0.0.0.0/0\n-k\n192.0.2.3\n")
        await #expect(throws: DaemonFailure.pfToken) { try await runner.release(token: "1\n-X 2") }
        #expect(fixture.count == 6)
    }

    #if WGEX_LAB_BUILD
        @Test
        func `lab adapter refuses the host without spawning a process`() async {
            await #expect(throws: DaemonFailure.pfUnavailable) {
                try await SystemPacketFilterSystem().run(arguments: [], input: Data(), deadline: 1)
            }
        }
    #endif
}

@Suite(.timeLimit(.minutes(15)))
private struct PacketFilterExtraRunnerTests {
    @Test(arguments: [false, true])
    func `stock anchor check always records sibling argv`(present: Bool) async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "stdout", present ? "anchor \"com.apple/*\" all\n" : "scrub-anchor \"com.apple/*\" all\n")
        try fixture.reply(2, "stdout", PFTranscripts.stdout("anchors"))
        let runner = fixture.runner
        if present {
            #expect(try await runner.verifyStockAnchor() == PFTranscripts.stdout("anchors"))
        } else {
            await #expect(throws: DaemonFailure.pfVerification) { try await runner.verifyStockAnchor() }
        }
        #expect(try fixture.recorded(1, "argv") == "-s\nrules\n")
        #expect(try fixture.recorded(2, "argv") == "-a\ncom.apple\n-s\nAnchors\n-v\n")
    }

    @Test
    func `fake canary and enabled status parse exact output fields`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "stdout", "@1 block drop quick all label \"wgex-canary\"\n [ Evaluations: 18 Packets: 2 Bytes: 80 ]\n")
        try fixture.reply(2, "stdout", PFTranscripts.enabledInfo(true))
        try fixture.reply(3, "stdout", PFTranscripts.enabledInfo(false))
        let runner = fixture.runner
        #expect(try await runner.canaryEvaluations() == 18)
        #expect(try await runner.isEnabled())
        #expect(try await !runner.isEnabled())
        await #expect(throws: DaemonFailure.pfVerification) { try await runner.canaryEvaluations() }
        #expect(try fixture.recorded(1, "argv") == "-a\ncom.apple/wgex\n-vsr\n")
        #expect(try fixture.recorded(2, "argv") == "-s\ninfo\n")
    }

    @Test
    func `enable accepts stdout token but rejects malformed output`() async throws {
        let fixture = try PFFixture(); defer { fixture.cleanup() }
        try fixture.reply(1, "stdout", PFTranscripts.read("enable", token: "42"))
        try fixture.reply(2, "stderr", "pf enabled but no token\n")
        let runner = fixture.runner
        #expect(try await runner.enable() == "42")
        await #expect(throws: DaemonFailure.pfToken) { try await runner.enable() }
    }

    @Test
    func `IPv6 host fallback uses IPv6 wildcard and retains interface scope`() throws {
        let strategy = try PFCtl.StateKill.hosts(interface: PFInterface("en2"), addresses: [PFAddress("2001:db8::2")])
        #expect(strategy.arguments == [["-i", "en2", "-k", "2001:db8::2"], ["-i", "en2", "-k", "::/0", "-k", "2001:db8::2"]])
    }
}
