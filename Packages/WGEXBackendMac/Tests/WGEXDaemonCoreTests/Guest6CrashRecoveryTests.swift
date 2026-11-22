// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// M1-20 (guest run 6 slice 4, D16): after SIGKILL or SIGTERM the relaunched daemon recovered its pf reference and then,
/// until `preparing`, loaded a recovery anchor that let probes to the vmnet host 192.168.64.1 leave en0 for 1.0-1.5 s.
/// The replay starts from the dead daemon's ruleset, its one reference and the journal, drives the production startup
/// order (mark recovering, prepare blocking, reconcile) and evaluates every anchor state with the lab's probes.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6CrashRecoveryTests {
    enum Exit: String, CaseIterable, Sendable { case sigkill, sigterm }

    private static let anchor = PacketFilterRenderer.anchor

    /// The slice-4 report's post-recovery order with the anchor left untouched after `pf: token recovered`.
    private static let recoveryPrefix: [[String]] = [
        ["-o", "none", "-n", "-a", anchor, "-f", "-"],
        ["-o", "none", "-a", anchor, "-f", "-"],
        ["-a", anchor, "-sr"],
        ["-s", "rules"],
        ["-s", "References"],
        ["-i", "en0", "-F", "states"],
        ["-a", anchor, "-vsr"],
    ]

    @Test(arguments: Exit.allCases)
    func `M1-20 crash recovery never loads an anchor that passes traffic to the underlay host`(_ exit: Exit) async throws {
        let replay = try await CrashReplay(exit)
        for probe in PFProbe.lab {
            #expect(try !PFAnchorModel.passes(replay.deadAnchor, probe), "dead daemon's ruleset passes \(probe)")
        }
        try await replay.run()
        let steps = await replay.system.steps
        #expect(Array(steps.prefix(Self.recoveryPrefix.count).map(\.arguments)) == Self.recoveryPrefix)
        for (index, step) in steps.enumerated() {
            #expect(!step.anchor.isEmpty, "empty anchor at step \(index) \(step.arguments)")
            for probe in PFProbe.lab {
                #expect(try !PFAnchorModel.passes(step.anchor, probe), "step \(index) \(step.arguments) passes \(probe)")
            }
            #expect(step.references == 1, "step \(index) holds \(step.references) references")
        }
        #expect(!steps.contains { $0.arguments == ["-E"] || $0.arguments.first == "-X" })
        try await expectTruthfulStatus(steps, replay: replay)
        // Once the intended profile reached the port, Allow LAN is honoured behind the profile's tunnel-range block.
        let final = await replay.system.anchor
        let block = try #require(final.range(of: "block drop out quick on en0 inet from any to <wgex_"))
        let lan = try #require(final.range(of: "pass quick on en0 inet from 192.168.64.0/24 to 192.168.64.0/24 no state"))
        #expect(block.lowerBound < lan.lowerBound)
    }

    /// Status reads `unknown` until the recovery anchor's read-back and canary verify it; never blocked before.
    private func expectTruthfulStatus(_ steps: [CrashReplayPF.Step], replay: CrashReplay) async throws {
        let verified = try #require(steps.firstIndex { $0.arguments == ["-a", Self.anchor, "-vsr"] })
        for step in steps[...verified] {
            #expect(step.protection == .unknown, "status \(String(describing: step.protection)) before verification")
        }
        for (index, step) in steps.enumerated() {
            #expect(step.protection == .unknown || step.protection == .blocked)
            if step.protection == .blocked {
                let open = try PFProbe.lab.filter { try PFAnchorModel.passes(step.anchor, $0) }
                #expect(open.isEmpty, "status blocked at step \(index) \(step.arguments) while the anchor passes \(open)")
            }
        }
        #expect(await replay.controller.status.protection == .blocked)
        #expect(await replay.policy.current() == .error)
    }

    @Test
    func `M1-20 lockdown without an intent keeps the Allow LAN setting after recovery`() async throws {
        let replay = try await CrashReplay(.sigkill, lockdownWithoutIntent: true)
        try await replay.run()
        let steps = await replay.system.steps
        #expect(steps.allSatisfy { $0.references == 1 && !$0.anchor.isEmpty })
        #expect(await replay.system.anchor.contains("pass quick on en0 inet from 192.168.64.0/24 to 192.168.64.0/24 no state"))
        #expect(await replay.controller.status.protection == .blocked)
        #expect(await replay.policy.current() == .lockdown)
    }

    @Test
    func `M1-20 anchor model passes the pre-fix recovery anchor and an empty one`() throws {
        let lanContext = try PFContext(
            underlay: PFInterface("en0"), resolvers: [PFAddress("192.168.64.1")],
            lanSubnets: [IPAddressRange("192.168.64.0/24")], consoleUID: 501,
        )
        let preFix = try PacketFilterRenderer.render(
            phase: .error, modifiers: PFModifiers(allowLAN: true, canary: .ipv4), context: lanContext,
        )
        #expect(try PFAnchorModel.passes(preFix, PFProbe.lab[0]))
        #expect(try PFAnchorModel.passes("", PFProbe.lab[0]))
        #expect(try !PFAnchorModel.passes(preFix, PFProbe.lab[4]))
    }

    #if WGEX_LAB_BUILD
        @Test(arguments: Exit.allCases)
        func `M1-20 recovery names its anchor steps in order with fixed text`(_ exit: Exit) async throws {
            let replay = try await CrashReplay(exit), lines = Mutex<[String]>([])
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                try await replay.run()
            }
            let output = lines.withLock { $0.filter { $0.hasPrefix("recovery:") || $0.hasPrefix("pf:") } }
            #expect(output == ["recovery: anchor rendered", "pf: token recovered", "recovery: anchor kept", "recovery: anchor verified"])
        }

        @Test
        func `M1-20 recovery labels are fixed text`() {
            for step in DaemonDiagnostics.RecoveryStep.allCases {
                let label = "recovery: " + (DaemonDiagnostics.recoveryLabels[step] ?? "")
                #expect(label.range(of: "^recovery: anchor (kept|rendered|verified)$", options: .regularExpression) != nil)
            }
        }
    #endif
}

/// The dead daemon's state: its last ruleset in the anchor, one reference, the journalled intent and token.
private struct CrashReplay {
    static let boot = UUID()
    static let lan = "192.168.64.0/24"
    let harness: ControllerHarness
    let system: CrashReplayPF
    let policy: PolicyEnforcer
    let controller: TunnelController
    let deadAnchor: String

    init(_ exit: Guest6CrashRecoveryTests.Exit, lockdownWithoutIntent: Bool = false) async throws {
        let underlay = try UnderlaySnapshot(
            v4: 4, v6: nil, resolvers: ["192.168.64.1"], interfaceNames: ["en0"], interfaceV4Name: "en0",
            lanSubnets: [IPAddressRange(Self.lan)],
        )
        harness = try ControllerHarness(underlay: underlay)
        var profile = harness.profile
        profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/1"), IPAddressRange("128.0.0.0/1")]
        try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        deadAnchor = try Self.deadAnchor(exit, profile: profile, lockdown: lockdownWithoutIntent)
        let connected = PacketFilterPolicy.connected(interfaceName: "utun7", endpoints: ["192.168.64.1:51820"])
        try harness.journal.mutate(generation: nil) {
            $0.intent = lockdownWithoutIntent ? nil : TunnelIntent(profileID: profile.id, ownerUID: ControllerHarness.uid)
            $0.settings = MacGlobalSettings(lockdown: lockdownWithoutIntent, allowLAN: true, captiveWindowSeconds: 300, notifications: true)
            $0.pfPolicy = lockdownWithoutIntent ? .lockdown : (exit == .sigkill ? connected : .error)
            $0.pfToken = "99"; $0.pfTokenPID = 123; $0.pfBootSession = Self.boot
            // SIGTERM's orderly shutdown applied `.error`, kept the reference and wrote the checkpoint.
            $0.cleanShutdownAt = exit == .sigterm ? Date() : nil
        }
        let system = CrashReplayPF(anchor: deadAnchor, token: "99", pid: 123)
        self.system = system
        policy = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: ControllerHarness.uid),
            canaryProbe: { await system.probe() }, bootSession: Self.boot,
        )
        let ports = harness.ports
        controller = TunnelController(
            registry: harness.registry, secureInstall: VerifiedSecureInstall(), journal: harness.journal, secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: ports, routes: ports, dns: ports, policy: policy, resolver: ports,
                device: ports, verifier: ports, reality: ports,
            ),
            underlay: underlay, clock: harness.clock, operationClock: harness.clock,
        )
        #expect(controller.previousShutdownWasClean == (exit == .sigterm))
        await system.observe { [controller] in await controller.status.protection }
    }

    /// The production startup order: the listener marks recovery, then blocking is prepared, then reconciliation runs.
    func run() async throws {
        await controller.markStartupRecovering()
        try await controller.prepareStartupBlocking()
        try await controller.reconcileAtStartup()
    }

    private static func deadAnchor(_ exit: Guest6CrashRecoveryTests.Exit, profile: TunnelProfile, lockdown: Bool) throws -> String {
        let killed = exit == .sigkill && !lockdown
        let ranges = profile.interface.addresses + profile.peers.flatMap(\.allowedIPs)
        let context = try PFContext(
            underlay: PFInterface("en0"), tunnel: killed ? PFInterface("utun7") : nil,
            endpoints: killed ? [PFEndpoint("192.168.64.1:51820")] : [], resolvers: [PFAddress("192.168.64.1")],
            tunnelDNS: [PFAddress("10.77.0.1")], lanSubnets: [IPAddressRange(lan)], tunnelRanges: ranges, consoleUID: 501,
        )
        let modifiers = PFModifiers(allowLAN: true, ipv6Policy: profile.protection.ipv6Policy, canary: .ipv4)
        return try PacketFilterRenderer.render(
            phase: lockdown ? .lockdown : (killed ? .connected : .error),
            modifiers: modifiers,
            context: context,
        )
    }
}

/// macOS 26 pfctl replies from the captured transcripts; records the anchor, the published protection and the
/// reference count at every command the daemon issues.
private actor CrashReplayPF: PacketFilterSystem {
    struct Step: Sendable {
        let arguments: [String]
        let anchor: String
        let protection: ProtectionState?
        let references: Int
    }

    private(set) var anchor: String
    private(set) var steps: [Step] = []
    private var references: [String: Int32]
    private var counter: UInt64 = 0
    private var status: (@Sendable () async -> ProtectionState)?

    init(anchor: String, token: String, pid: Int32) {
        self.anchor = anchor
        references = [token: pid]
    }

    func observe(_ status: @escaping @Sendable () async -> ProtectionState) {
        self.status = status
    }

    func probe() {
        counter += 1
    }

    func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        try beforeExec(456)
        return try await run(arguments: ["-E"], input: Data(), deadline: deadline)
    }

    func run(arguments: [String], input: Data, deadline _: TimeInterval) async throws -> PFCommandResult {
        let protection = await status?()
        let result = try respond(arguments, input: input)
        steps.append(Step(arguments: arguments, anchor: anchor, protection: protection, references: references.count))
        return result
    }

    private func respond(_ arguments: [String], input: Data) throws -> PFCommandResult {
        if let reply = try ownership(arguments) {
            return reply
        }
        let name = PacketFilterRenderer.anchor
        switch arguments {
        case ["-s", "rules"]: return try PFCommandResult(stdout: PFTranscripts.stdout("rules"), stderr: PFTranscripts.preamble)
        case ["-s", "info"]: return try PFCommandResult(stdout: PFTranscripts.enabledInfo(true), stderr: PFTranscripts.preamble)
        case ["-o", "none", "-a", name, "-f", "-"]: anchor = String(decoding: input, as: UTF8.self); counter = 0
        case ["-a", name, "-sr"]: return PFCommandResult(stdout: anchor, stderr: PFTranscripts.preamble)
        case ["-a", name, "-vsr"]: return PFCommandResult(stdout: verbosePF(anchor, counter: counter), stderr: PFTranscripts.preamble)
        case ["-a", "com.apple", "-s", "Anchors", "-v"]:
            return try PFCommandResult(stdout: PFTranscripts.stdout("anchors"), stderr: PFTranscripts.preamble)
        default: break
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }

    /// Reference table, enable, release and table reads; nil for every other command.
    private func ownership(_ arguments: [String]) throws -> PFCommandResult? {
        if arguments.contains("-T"), arguments.last == "show" {
            return PFCommandResult(stdout: pfTableOutput(anchor))
        }
        switch arguments {
        case ["-E"]:
            references["100"] = 456
            return try PFCommandResult(stderr: PFTranscripts.read("enable", token: "100"))
        case ["-s", "References"]:
            let rows = references.sorted { $0.value < $1.value }.map { PFTranscripts.Reference(pid: $0.value, token: $0.key) }
            return try PFCommandResult(stdout: PFTranscripts.references(rows), stderr: PFTranscripts.preamble)
        default:
            if arguments.first == "-X", let token = arguments.last {
                references[token] = nil
            }
            return nil
        }
    }
}

/// One outbound probe as the lab's guest sent it from 192.168.64.64 on en0.
private struct PFProbe: Sendable, CustomStringConvertible {
    enum Proto: String, Sendable { case tcp, udp }
    let proto: Proto
    let destination: String
    let port: UInt16
    var uid: UInt32 = 501
    var description: String {
        "\(proto.rawValue) \(destination):\(port) uid \(uid)"
    }

    /// The slice-4 receivers (http/tcp/udp 8088, dns 5354 on the vmnet host), a root sender, and a non-LAN host.
    static let lab: [PFProbe] = [
        .init(proto: .tcp, destination: "192.168.64.1", port: 8088),
        .init(proto: .udp, destination: "192.168.64.1", port: 8088),
        .init(proto: .udp, destination: "192.168.64.1", port: 5354),
        .init(proto: .tcp, destination: "192.168.64.1", port: 8088, uid: 0),
        .init(proto: .tcp, destination: "203.0.113.7", port: 443),
    ]
}

/// First-match evaluation of the renderer's grammar (every rule is quick). Unknown syntax fails the test rather than
/// guessing; an anchor with no matching rule leaves the packet to the permissive stock ruleset.
private enum PFAnchorModel {
    struct SyntaxError: Error { let line: String }

    static func passes(_ anchor: String, _ probe: PFProbe) throws -> Bool {
        var tables: [String: [IPAddressRange]] = [:]
        for line in anchor.split(separator: "\n").map(String.init) {
            if line.hasPrefix("table <") {
                guard let close = line.firstIndex(of: ">"), let open = line.firstIndex(of: "{"), let end = line.lastIndex(of: "}")
                else { throw SyntaxError(line: line) }
                let name = String(line[line.index(line.startIndex, offsetBy: 7) ..< close])
                tables[name] = try line[line.index(after: open) ..< end].split(separator: ",")
                    .map { try IPAddressRange($0.trimmingCharacters(in: .whitespaces)) }
                continue
            }
            let rule = try PFModelRule(line)
            if try rule.matches(probe, tables: tables) {
                return rule.pass
            }
        }
        return true
    }
}

private struct PFModelRule {
    var pass = false
    var direction: String?
    var interface: String?
    var family: String?
    var proto: String?
    var source = "any", destination = "any"
    var sourcePort: UInt16?, destinationPort: UInt16?
    var user: UInt32?
    var group: UInt32?

    init(_ line: String) throws {
        var words = line.split(separator: " ").map(String.init)[...]
        let head = words.popFirst()
        if head == "pass" {
            pass = true
        } else if head != "block" || words.popFirst() != "drop" {
            throw PFAnchorModel.SyntaxError(line: line)
        }
        while let word = words.popFirst() {
            guard try readMatch(word, &words) || readOption(word, &words) else { throw PFAnchorModel.SyntaxError(line: line) }
        }
    }

    private static func next(_ words: inout ArraySlice<String>) throws -> String {
        guard let word = words.popFirst() else { throw PFAnchorModel.SyntaxError(line: "truncated rule") }
        return word
    }

    private static func port(_ words: inout ArraySlice<String>) throws -> UInt16? {
        guard words.first == "port" else { return nil }
        words.removeFirst()
        return try UInt16(next(&words))
    }

    /// Packet-matching keywords; false for a keyword this reader does not own.
    private mutating func readMatch(_ word: String, _ words: inout ArraySlice<String>) throws -> Bool {
        switch word {
        case "in", "out": direction = word
        case "on": interface = try Self.next(&words)
        case "inet", "inet6": family = word
        case "proto": proto = try Self.next(&words)
        case "from": source = try Self.next(&words); sourcePort = try Self.port(&words)
        case "to": destination = try Self.next(&words); destinationPort = try Self.port(&words)
        case "user": user = try UInt32(Self.next(&words))
        default: return false
        }
        return true
    }

    /// Keywords that never widen a match (state, labels, ICMP types of other protocols) and the resolver group.
    private mutating func readOption(_ word: String, _ words: inout ArraySlice<String>) throws -> Bool {
        switch word {
        case "quick", "all": return true
        case "group":
            guard try Self.next(&words) == "=" else { return false }
            group = try UInt32(Self.next(&words))
        case "route-to", "icmp-type", "icmp6-type", "code", "flags", "label": _ = try Self.next(&words)
        case "keep", "no": return try Self.next(&words) == "state"
        default: return false
        }
        return true
    }

    func matches(_ probe: PFProbe, tables: [String: [IPAddressRange]]) throws -> Bool {
        guard direction ?? "out" == "out", interface ?? "en0" == "en0", family ?? "inet" == "inet",
              proto ?? probe.proto.rawValue == probe.proto.rawValue, sourcePort ?? 49174 == 49174,
              destinationPort ?? probe.port == probe.port, user ?? probe.uid == probe.uid,
              group == nil else { return false }
        return try Self.address(source, contains: "192.168.64.64", tables)
            && Self.address(destination, contains: probe.destination, tables)
    }

    private static func address(_ spec: String, contains host: String, _ tables: [String: [IPAddressRange]]) throws -> Bool {
        if spec == "any" {
            return true
        }
        let target = try IPAddressRange(host)
        if spec.hasPrefix("<"), spec.hasSuffix(">") {
            guard let table = tables[String(spec.dropFirst().dropLast())] else { throw PFAnchorModel.SyntaxError(line: spec) }
            return table.contains { $0.contains(target) }
        }
        return try IPAddressRange(spec).contains(target)
    }
}
