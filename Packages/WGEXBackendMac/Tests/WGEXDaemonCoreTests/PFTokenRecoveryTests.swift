// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private final class RecoveryPFJournal: PFTokenJournalling {
    private let state: Mutex<PFTokenState>
    private let failTokenCommit: Bool
    init(_ value: PFTokenState = PFTokenState(), failTokenCommit: Bool = false) {
        state = Mutex(value)
        self.failTokenCommit = failTokenCommit
    }

    func readState() -> PFTokenState {
        state.withLock { $0 }
    }

    func writeState(_ value: PFTokenState) throws {
        if failTokenCommit, value.token != nil {
            throw DaemonFailure.pfJournal
        }
        state.withLock { $0 = value }
    }

    func readToken() -> String? {
        readState().token
    }

    func writeToken(_ token: String?) {
        state.withLock { $0.token = token }
    }
}

/// Models macOS 26 reference ownership, including an enable whose output cannot be parsed.
private actor RecoveryPFSystem: PacketFilterSystem {
    var calls: [[String]] = []
    var references: [Int32: (String, String)] = [:]
    var text = ""
    var ages: [Int32: Int] = [:]
    var malformedEnable = false
    var enableAttemptWasDurable = false
    var counter: UInt64 = 0
    func probe() {
        counter += 1
    }

    let journal: RecoveryPFJournal
    init(journal: RecoveryPFJournal) {
        self.journal = journal
    }

    func row(pid: Int32, process: String = "pfctl", token: String, age: Int = 1) {
        references[pid] = (process, token)
        ages[pid] = age
    }

    func corruptEnable() {
        malformedEnable = true
    }

    func externallyRelease() {
        references = [:]
    }

    func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        try beforeExec(456)
        enableAttemptWasDurable = journal.readState().attempt?.pid == 456
        return try run(arguments: ["-E"], input: Data(), deadline: deadline)
    }

    private func enableResult() throws -> PFCommandResult {
        references[456] = ("pfctl", "100")
        return try PFCommandResult(
            stderr: malformedEnable ? PFTranscripts.preamble + "pf enabled\n" : PFTranscripts.read("enable", token: "100"),
        )
    }

    private func releaseResult(_ arguments: [String]) -> PFCommandResult {
        if arguments.first == "-X", let token = arguments.last {
            references = references.filter { $0.value.1 != token }
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }

    func run(arguments: [String], input: Data, deadline: TimeInterval) throws -> PFCommandResult {
        calls.append(arguments)
        if arguments.contains("-T"), arguments.last == "show" {
            return PFCommandResult(stdout: pfTableOutput(text))
        }
        switch arguments {
        case ["-E"]:
            return try enableResult()
        case ["-s", "References"]:
            return try PFCommandResult(
                stdout: PFTranscripts.references(references.sorted { $0.key < $1.key }.map {
                    .init(pid: $0.key, process: $0.value.0, token: $0.value.1, age: ages[$0.key] ?? 1)
                }),
                stderr: PFTranscripts.preamble,
            )
        case ["-s", "rules"]: return try PFCommandResult(stdout: PFTranscripts.stdout("rules"), stderr: PFTranscripts.preamble)
        case ["-s", "info"]: return try PFCommandResult(stdout: PFTranscripts.enabledInfo(true), stderr: PFTranscripts.preamble)
        case ["-o", "none", "-a", "com.apple/wgex", "-f", "-"]: text = String(decoding: input, as: UTF8.self); counter = 0
        case ["-a", "com.apple/wgex", "-sr"]: return PFCommandResult(stdout: text, stderr: PFTranscripts.preamble)
        case ["-a", "com.apple", "-s", "Anchors", "-v"]:
            return try PFCommandResult(stdout: PFTranscripts.stdout("anchors"), stderr: PFTranscripts.preamble)
        case ["-a", "com.apple/wgex", "-vsr"]:
            return PFCommandResult(
                stdout: verbosePF(text, counter: UInt64(counter)),
                stderr: PFTranscripts.preamble,
            )
        default: return releaseResult(arguments)
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct PFTokenRecoveryTests {
    let bootA = UUID()
    let bootB = UUID()

    @Test
    func `controller reboot never adopts a previous boot token even when its number is present`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        try harness.journal.mutate(generation: nil) {
            $0.intent = TunnelIntent(profileID: harness.profile.id, ownerUID: 501)
            $0.pfPolicy = .error; $0.pfToken = "99"; $0.pfTokenPID = 123; $0.pfBootSession = bootA
        }
        let system = RecoveryPFSystem(journal: RecoveryPFJournal())
        await system.row(pid: 123, token: "99")
        let policy = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() }, bootSession: bootB,
        )
        let ports = harness.ports
        let controller = TunnelController(
            registry: harness.registry, secureInstall: VerifiedSecureInstall(), journal: harness.journal, secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: ports, routes: ports, dns: ports, policy: policy, resolver: ports,
                device: ports, verifier: ports, reality: ports,
            ),
            underlay: .init(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"]),
            clock: harness.clock, operationClock: harness.clock,
        )
        try await controller.reconcileAtStartup()
        #expect(harness.journal.snapshot().pfBootSession == bootB)
        #expect(harness.journal.snapshot().pfToken == "100")
        #expect(await !system.calls.contains(["-X", "99"]))
        #expect(await system.calls.filter { $0 == ["-E"] }.count == 1)
        #expect(await controller.status.protection == .blocked)
    }

    @Test
    func `failed token commit compensates its durable enable attempt and preserves blocking`() async throws {
        let journal = RecoveryPFJournal(failTokenCommit: true)
        let system = RecoveryPFSystem(journal: journal)
        let enforcer = try make(journal, system, boot: bootA)
        await #expect(throws: (any Error).self) { try await enforcer.apply(.error) }
        #expect(await system.enableAttemptWasDurable)
        #expect(await system.references.isEmpty)
        #expect(journal.readState().attempt == nil)
        #expect(journal.readToken() == nil)
        #expect(await enforcer.current() == .error)
        #expect(await enforcer.verificationStatus == .unknown)
        let calls = await system.calls
        let enable = try #require(calls.firstIndex(of: ["-E"]))
        let release = try #require(calls.firstIndex(of: ["-X", "100"]))
        #expect(enable < release)
        #expect(calls.filter { $0 == ["-E"] }.count == 1)
        #expect(calls.filter { $0 == ["-X", "100"] }.count == 1)
    }

    @Test(arguments: [false, true])
    func `same boot failed controller retains intent and adopts or reacquires its token`(_ referenceMissing: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        try harness.journal.mutate(generation: nil) {
            $0.intent = TunnelIntent(profileID: harness.profile.id, ownerUID: 501)
            $0.pfPolicy = .error; $0.pfToken = "99"; $0.pfTokenPID = 123; $0.pfBootSession = bootA
        }
        let system = RecoveryPFSystem(journal: RecoveryPFJournal())
        if !referenceMissing {
            await system.row(pid: 123, token: "99")
        }
        let policy = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
            bootSession: bootA,
        )
        let ports = harness.ports
        let controller = TunnelController(
            registry: harness.registry,
            secureInstall: VerifiedSecureInstall(),
            journal: harness.journal,
            secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: ports,
                routes: ports,
                dns: ports,
                policy: policy,
                resolver: ports,
                device: ports,
                verifier: ports,
                reality: ports,
            ),
            underlay: UnderlaySnapshot(v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"]),
            clock: harness.clock,
            operationClock: harness.clock,
        )
        try await controller.consoleUserChanged(nil)
        try await controller.reconcileAtStartup()
        let state = harness.journal.snapshot()
        #expect(state.intent?.profileID == harness.profile.id)
        #expect(state.pfToken == (referenceMissing ? "100" : "99"))
        #expect(state.pfBootSession == bootA)
        #expect(state.pfTokenPID == (referenceMissing ? 456 : 123))
        #expect(await controller.status.protection == .blocked)
        #expect(await policy.current() == .error)
        #expect(await !system.calls.contains { $0.first == "-X" })
        #expect(await system.calls.filter { $0 == ["-E"] }.count == (referenceMissing ? 1 : 0))
    }

    @Test(arguments: [false, true])
    func `reboot and missing same boot token block before query and never release stale token`(reboot: Bool) async throws {
        let journal = RecoveryPFJournal(PFTokenState(token: "99", bootSession: bootA, pid: 123))
        let system = RecoveryPFSystem(journal: journal)
        let enforcer = try make(journal, system, boot: reboot ? bootB : bootA)
        try await enforcer.apply(.error)
        let calls = await system.calls
        let block = try #require(calls.firstIndex(of: ["-o", "none", "-a", "com.apple/wgex", "-f", "-"]))
        let enable = try #require(calls.firstIndex(of: ["-E"]))
        #expect(block < enable)
        if let query = calls.firstIndex(of: ["-s", "References"]) {
            #expect(block < query)
        }
        #expect(!calls.contains(["-X", "99"]))
        #expect(journal.readState().bootSession == (reboot ? bootB : bootA))
        #expect(journal.readToken() == "100")
        #expect(await system.enableAttemptWasDurable)
        #expect(journal.readState().attempt == nil)
    }

    @Test
    func `open write ahead attempt releases only matching child process on this boot`() async throws {
        let attempt = PFEnableAttempt(bootSession: bootA, pid: 123, at: Date())
        let journal = RecoveryPFJournal(PFTokenState(attempt: attempt))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: 123, token: "88")
        await system.row(pid: 321, process: "other", token: "77")
        let enforcer = try make(journal, system, boot: bootA)
        try await enforcer.apply(.error)
        #expect(await system.calls.contains(["-X", "88"]))
        #expect(await !system.calls.contains(["-X", "77"]))
        #expect(await system.references.count == 2)
    }

    @Test(arguments: [false, true])
    func `attempt from another boot or another process is never released`(otherBoot: Bool) async throws {
        let journal = RecoveryPFJournal(PFTokenState(attempt: PFEnableAttempt(bootSession: bootA, pid: 123, at: Date())))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: 123, process: otherBoot ? "pfctl" : "other", token: "88")
        let enforcer = try make(journal, system, boot: otherBoot ? bootB : bootA)
        try await enforcer.apply(.error)
        #expect(await !system.calls.contains(["-X", "88"]))
    }

    @Test
    func `successful enable with unparsable output compensates by child pid without leaking`() async throws {
        let journal = RecoveryPFJournal()
        let matchingSystem = RecoveryPFSystem(journal: journal)
        await matchingSystem.corruptEnable()
        let enforcer = try make(journal, matchingSystem, boot: bootA)
        await #expect(throws: (any Error).self) { try await enforcer.apply(.error) }
        #expect(await matchingSystem.enableAttemptWasDurable)
        #expect(await matchingSystem.references.isEmpty)
        #expect(journal.readState().attempt == nil)
    }

    @Test
    func `external release reacquires once and emits one fixed diagnostic`() async throws {
        let journal = RecoveryPFJournal(PFTokenState(token: "99", bootSession: bootA, pid: 123))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: 123, token: "99")
        let logs = Mutex(0)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 0), bootSession: bootA,
            onExternalRelease: { logs.withLock { $0 += 1 } },
        )
        try await enforcer.apply(.error)
        await system.externallyRelease()
        let adapter = PolicyLivenessAdapter(policy: enforcer, runner: PFCtl(system: system))
        #expect(try await adapter.repairLiveness(existingToken: "99") == "100")
        #expect(try await adapter.repairLiveness(existingToken: "100") == "100")
        #expect(logs.withLock { $0 } == 1)
        #expect(await system.references.count == 1)
        #expect(await system.calls.filter { $0 == ["-E"] }.count == 1)
        #expect(await !system.calls.contains(["-X", "99"]))
    }

    @Test(arguments: [false, true])
    func `reused token with a foreign pid or process is neither adopted nor released`(wrongPID: Bool) async throws {
        let journal = RecoveryPFJournal(PFTokenState(token: "99", bootSession: bootA, pid: 123))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: wrongPID ? 321 : 123, process: wrongPID ? "pfctl" : "other", token: "99")
        let enforcer = try make(journal, system, boot: bootA)
        try await enforcer.apply(.error)
        #expect(journal.readToken() == "100")
        #expect(await !system.calls.contains(["-X", "99"]))
    }

    @Test
    func `old reference with the attempted pid is not compensated`() async throws {
        let journal = RecoveryPFJournal(PFTokenState(attempt: .init(bootSession: bootA, pid: 123, at: Date())))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: 123, token: "88", age: 3600)
        try await make(journal, system, boot: bootA).apply(.error)
        #expect(await !system.calls.contains(["-X", "88"]))
    }

    @Test
    func `reused pid with a newer foreign reference is outside the enable window`() async throws {
        let journal = RecoveryPFJournal(PFTokenState(attempt: .init(
            bootSession: bootA,
            pid: 123,
            at: Date().addingTimeInterval(-3600),
        )))
        let system = RecoveryPFSystem(journal: journal)
        await system.row(pid: 123, token: "88")
        try await make(journal, system, boot: bootA).apply(.error)
        #expect(await !system.calls.contains(["-X", "88"]))
    }

    @Test
    func `reference parser skips noise and preserves process names with spaces`() throws {
        let text = try PFTranscripts.references([
            .init(pid: 123, process: "a process with spaces", token: "99", age: 3),
            .init(pid: 321, token: "100", age: 1),
        ])
        let rows = try PacketFilterReadback.references(PFTranscripts.preamble + "unexpected kernel warning\n" + text + "invalid row\n")
        #expect(rows.count == 2)
        #expect(rows.first?.process == "a process with spaces")
        #expect(rows.first?.token == "99")
        let unknownStamp = try PacketFilterReadback.references("123 pfctl 99 future-format")
        #expect(unknownStamp.first?.token == "99")
        #expect(unknownStamp.first?.matchesAttempt(at: Date(), now: Date()) == false)
    }

    private func make(_ journal: RecoveryPFJournal, _ system: RecoveryPFSystem, boot: UUID) throws -> PolicyEnforcer {
        try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 0), bootSession: boot,
        )
    }
}
