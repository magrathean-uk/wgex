// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

private actor CompositionPFSystem: PacketFilterSystem {
    enum Fault: Sendable, CaseIterable { case none, readback, stockAnchor, deadCanary }
    var fault: Fault
    var canary = 1
    var loaded = ""
    var calls: [[String]] = []
    let journal: any PFTokenJournalling
    var tokenBeforeLoad = false
    var liveTokens: [String] = []
    var refuseCaptive = false
    func refuseCaptivePolicy() {
        refuseCaptive = true
    }

    init(fault: Fault, journal: any PFTokenJournalling) {
        self.fault = fault; self.journal = journal
        if let token = try? journal.readToken() {
            liveTokens = [token]
        }
    }

    func probe() {
        if fault != .deadCanary {
            canary += 1
        }
    }

    func failReadback() {
        fault = .readback
    }

    func restoreReadback() {
        fault = .none
    }

    func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        try beforeExec(123)
        return try run(arguments: ["-E"], input: Data(), deadline: deadline)
    }

    private func scripted(_ arguments: [String], input: Data) -> PFCommandResult? {
        if refuseCaptive, arguments.contains("-f"), String(decoding: input, as: UTF8.self).contains("port 80 user") {
            return PFCommandResult(status: 2)
        }
        if arguments.contains("-T"), arguments.last == "show" {
            return PFCommandResult(stdout: pfTableOutput(loaded))
        }
        return nil
    }

    private func referenceCommand(_ arguments: [String]) throws -> PFCommandResult? {
        switch arguments {
        case ["-E"]:
            liveTokens.append("99")
            return try PFCommandResult(stderr: PFTranscripts.read("enable", token: "99"))
        case ["-X", "99"]:
            guard let index = liveTokens.firstIndex(of: "99") else { throw DaemonFailure.pfToken }
            liveTokens.remove(at: index)
        case ["-s", "References"]: return try PFCommandResult(
                stdout: PFTranscripts.references(liveTokens.map { .init(pid: 123, token: $0) }),
                stderr: PFTranscripts.preamble,
            )
        default: return nil
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }

    func run(arguments: [String], input: Data, deadline: TimeInterval) throws -> PFCommandResult {
        calls.append(arguments)
        if let scripted = scripted(arguments, input: input) {
            return scripted
        }
        if let reference = try referenceCommand(arguments) {
            return reference
        }
        switch arguments {
        case ["-s", "rules"]:
            return try PFCommandResult(stdout: fault == .stockAnchor ? "" : PFTranscripts.stdout("rules"), stderr: PFTranscripts.preamble)
        case ["-o", "none", "-a", "com.apple/wgex", "-f", "-"]:
            loaded = String(decoding: input, as: UTF8.self); canary = 0
            tokenBeforeLoad = try journal.readToken() == "99"
        case ["-a", "com.apple/wgex", "-sr"]:
            return PFCommandResult(stdout: fault == .readback ? "pass quick all\n" : loaded, stderr: PFTranscripts.preamble)
        case ["-a", "com.apple", "-s", "Anchors", "-v"]:
            return try PFCommandResult(stdout: PFTranscripts.stdout("anchors"), stderr: PFTranscripts.preamble)
        case ["-s", "info"]: return try PFCommandResult(stdout: PFTranscripts.enabledInfo(true), stderr: PFTranscripts.preamble)
        case ["-a", "com.apple/wgex", "-vsr"]:
            return PFCommandResult(
                stdout: verbosePF(fault == .readback ? "pass quick all\n" : loaded, counter: UInt64(canary)),
                stderr: PFTranscripts.preamble,
            )
        default: break
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }
}

private struct CompositionEngineVerifier: ProtectionVerifying {
    func verify(_ expectation: ProtectionExpectation) async throws {
        _ = try await expectation.engine.statistics()
    }
}

private struct CompositionNetwork: OwnedRouteInspecting, DaemonDNSConfiguring {
    let ports: HostPorts
    func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonFailure) {
        try await ports.install(routes, generation: generation)
    }

    func removeRoutes(of generation: Generation) async throws(DaemonFailure) {
        try await ports.removeRoutes(of: generation)
    }

    func ownedRoutes() async -> [RouteSpec] {
        await ports.ownedRoutes()
    }

    func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure) {
        try await ports.apply(configuration, generation: generation)
    }

    func remove(generation: Generation) async throws(DaemonFailure) {
        try await ports.remove(generation: generation)
    }

    func current() async -> DNSConfiguration? {
        await ports.current()
    }

    func observed(_ resources: GenerationResources) async -> [ObservedDaemonRoute] {
        guard let identity = await ports.identities[resources.generation] else { return [] }
        return await (ports.routeItems[resources.generation] ?? []).map {
            .init(route: $0, identity: identity, generation: resources.generation, hasProtocol2Flag: true)
        }
    }

    func reconcile(_ resources: GenerationResources) async throws {
        try await ports.install(
            resources.routes,
            generation: resources.generation,
        )
    }

    func verify(_ resources: GenerationResources) async throws {
        guard await ports.dnsItems[resources.generation] == resources.dns else { throw DaemonFailure.portNotOwned }
    }
}

private struct DaemonCompositionPFTests {
    @Test(arguments: ["engine.up", "routes.install"])
    func `failed generations retry once from intent within one start budget`(fault: String) async throws {
        let harness = try ControllerHarness()
        await harness.ports.setInterfaceName("utun7"); try await harness.install()
        let journal = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501), canaryProbe: { await system.probe() },
        )
        let controller = makeController(harness, enforcer: enforcer, measurePolicyInVerifier: true)
        harness.trace.fail(at: fault)
        await #expect(throws: (any Error).self) {
            _ = try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        }
        #expect(await system.calls.count <= 20)
        let engines = harness.trace.calls.filter { $0 == "engine.create" }.count
        for _ in 0 ..< 4 {
            harness.clock.advance(.seconds(1))
            let before = await system.calls.count
            try await controller.tick()
            #expect(await system.calls.count - before <= 2)
            #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
        }
        harness.clock.advance(.seconds(1))
        let before = await system.calls.count
        try await controller.tick()
        #expect(await system.calls.count - before <= 20)
        #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == engines + 1)
        #expect(await controller.status.protection == .protected)
    }

    @Test(arguments: [false, true])
    func `production policy call graph stays within start and steady tick spawn ceilings`(allowLAN: Bool) async throws {
        let harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) { $0.settings.allowLAN = allowLAN }
        await harness.ports.setInterfaceName("utun7")
        try await harness.install()
        let journal = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        let controller = makeController(harness, enforcer: enforcer, measurePolicyInVerifier: true)
        _ = try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        let start = await system.calls.count
        try await controller.tick()
        let tick = await system.calls.count - start
        let beforeRestart = await system.calls.count
        _ = try await controller.start(profileID: harness.profile.id, connectionUID: 501)
        let restart = await system.calls.count - beforeRestart
        harness.clock.advance(.seconds(5))
        let beforeTick = await system.calls.count
        try await controller.tick()
        let warmTick = await system.calls.count - beforeTick
        await controller.consume(
            .handshakeCompleted(peer: harness.profile.peers[0].publicKey, at: harness.clock.wallNow),
            generation: controller.currentGeneration,
        )
        for _ in 0 ..< 12 {
            harness.clock.advance(.seconds(5))
            let before = await system.calls.count
            try await controller.tick()
            #expect(await system.calls.count - before <= 2)
        }
        #expect(start <= 20); #expect(restart <= 20)
        #expect(tick <= 2); #expect(warmTick <= 2)
        guard let root = ProcessInfo.processInfo.environment["CLEAN_DEV_BUILDS"] else { return }
        #if WGEX_LAB_BUILD
            let variant = "lab"
        #else
            let variant = "plain"
        #endif
        let name = "M1-05-pf-counts-\(variant)-lan\(allowLAN ? 1 : 0).json"
        try JSONEncoder().encode(["start": start, "steadyTick": tick, "restart": restart, "warmTick": warmTick])
            .write(to: URL(fileURLWithPath: root).appendingPathComponent(name))
    }

    @Test(arguments: [CompositionPFSystem.Fault.readback, .stockAnchor, .deadCanary])
    func `real enforcer failures propagate unknown without a protection claim`(fault: CompositionPFSystem.Fault) async throws {
        let harness = try ControllerHarness()
        let shared = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: fault, journal: shared)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: shared,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: {},
        )
        let controller = makeController(harness, enforcer: enforcer)
        let composition = DaemonComposition(
            controller: controller,
            daemonVersion: "test",
            daemonBuild: 1,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
            statusJournal: StatusPublicationJournal(directory: harness.directory),
        )
        let transport = InMemoryXPCTransport(
            daemon: composition.dispatcher,
            peer: VerifiedPeerIdentity(
                uid: 501,
                pid: 7,
                auditSessionID: 10,
                codeSigningVerdict: .requirementSatisfied,
            ),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request, secrets: Data? = nil) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: secrets))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 1))
        #expect(try await call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .profileRevision(1))
        var wire = try ControllerHarness.bundle().wireBytes().withUnsafeBytes { Data($0) }
        defer { wire.resetBytes(in: 0 ..< wire.count) }
        let reply = try await call(.startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: true), secrets: wire)
        guard case let .error(.protectionUnknown(reason)) = reply else { Issue.record("No unknown reason"); return }
        #expect(reason.contains("cannot enforce")); #expect(reason.contains("Restart your Mac"))
        #expect(await controller.status.protection == .unknown)
        #expect(await enforcer.verificationStatus != .protected)
        if fault == .stockAnchor || fault == .readback {
            #expect(harness.journal.snapshot().pfToken == nil)
            #expect(await !system.calls.contains(["-E"]))
        } else {
            #expect(harness.journal.snapshot().pfToken == "99")
            #expect(await system.tokenBeforeLoad)
        }
        let kills = await system.calls.filter { $0.contains("states") }
        #expect(kills.allSatisfy { $0 == ["-i", "en0", "-F", "states"] })
    }

    @Test
    func `real enforcer verifies active captive and disconnect transitions then detects a live readback failure`() async throws {
        let harness = try ControllerHarness()
        await harness.ports.setInterfaceName("utun7")
        let journal = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let policy = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        let controller = makeController(harness, enforcer: policy)
        let fixture = CompositionFixture(harness: harness, controller: controller)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(await controller.status.protection == .protected)
        #expect(await policy.verificationStatus == .protected)
        let killsBeforeCaptive = await system.calls.filter { $0.contains("states") }.count
        #expect(try await fixture.call(.openCaptiveWindow(seconds: 10)) == .ok)
        #expect(await system.calls.filter { $0.contains("states") }.count == killsBeforeCaptive)
        #expect(try await fixture.call(.closeCaptiveWindow) == .ok)
        let killsBeforeStop = await system.calls.filter { $0.contains("states") }.count
        #expect(try await fixture.call(.stop(profileID: harness.profile.id, reason: .userRequested)) == .ok)
        #expect(await system.calls.filter { $0.contains("states") }.count == killsBeforeStop)
        #expect(harness.journal.snapshot().pfToken == nil)
        #expect(await system.calls.filter { $0 == ["-X", "99"] }.count == 1)
        _ = try await fixture.start()
        await system.failReadback()
        await #expect(throws: (any Error).self) { try await controller.tick() }
        #expect(await controller.status.protection == .unknown)
        try await verifyRestoredTokenOrdering(system, journal: journal)
    }

    private func verifyRestoredTokenOrdering(_ system: CompositionPFSystem, journal: DaemonPFTokenJournal) async throws {
        await system.restoreReadback()
        let before = await system.calls.count
        let restored = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
        )
        try await restored.apply(.error)
        let calls = await Array(system.calls.dropFirst(before))
        let block = try #require(calls.firstIndex(of: ["-o", "none", "-a", "com.apple/wgex", "-f", "-"]))
        let references = try #require(calls.firstIndex(of: ["-s", "References"]))
        #expect(block < references)
        #expect(!calls.contains(["-E"]))
        #expect(journal.readToken() == "99")
    }

    @Test
    func `connected commit uses the real PF port and kills only the complete underlay interface set`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.setInterfaceName("utun7")
        let journal = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501), canaryProbe: { await system.probe() },
        )
        let underlay = UnderlaySnapshot(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["en0", "en1"],
            interfaceV4Name: "en0", interfaceV6Name: "en1",
        )
        let controller = makeController(harness, enforcer: enforcer, measurePolicyInVerifier: true, underlay: underlay)
        let generation = try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        #expect(await controller.status.phase == .active(generation))
        guard case .connected = await enforcer.current() else { Issue.record("Real PF never applied connected policy"); return }
        let kills = await system.calls.filter { $0.contains("-F") && $0.contains("states") }
        #expect(kills.count == 2)
        #expect(Set(kills) == Set(underlay.interfaceNames.map { ["-i", $0, "-F", "states"] }))
        #expect(!kills.contains(["-F", "states"]))
    }

    private func makeController(
        _ harness: ControllerHarness, enforcer: PolicyEnforcer, measurePolicyInVerifier: Bool = false,
        underlay: UnderlaySnapshot = .init(v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"]),
        steps: any DaemonStepObserving = UninterruptedDaemonSteps(), policyPort: any DaemonPolicyManaging? = nil,
    ) -> TunnelController {
        let network = CompositionNetwork(ports: harness.ports)
        let clock: any DaemonClock = measurePolicyInVerifier ? harness.clock : ContinuousDaemonClock()
        let verifier: any ProtectionVerifying = measurePolicyInVerifier
            ? NetworkProtectionVerifier(routes: network, dns: network, identities: harness.ports, policy: enforcer) :
            CompositionEngineVerifier()
        return TunnelController(
            registry: harness.registry, secureInstall: VerifiedSecureInstall(),
            journal: harness.journal,
            secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: harness.ports,
                routes: harness.ports,
                dns: harness.ports,
                policy: policyPort ?? enforcer,
                resolver: harness.ports,
                device: harness.ports,
                verifier: verifier,
                reality: harness.ports,
            ),
            underlay: underlay,
            clock: clock,
            steps: steps,
        )
    }
}

private extension DaemonCompositionPFTests {
    @Test
    func `D11 cold PF connect with a recovered owned reference stays within twenty spawns`() async throws {
        let profile = try ControllerHarness.makeProfile(), journal = PFMemoryJournal(), boot = UUID()
        try journal.writeState(PFTokenState(token: "99", bootSession: boot, pid: 123))
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() }, bootSession: boot,
        )
        // The controller's three PF phases, starting with the runtime's recovered reference.
        try await enforcer.configureProfile(profile)
        _ = try await enforcer.acquireToken(existing: "99")
        try await enforcer.setModifiers(.init(
            allowLAN: true,
            captiveWindow: nil,
            consoleUID: 501,
            underlay: .init(v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"]),
        ))
        try await enforcer.apply(.connecting(resolvers: ["192.0.2.53"], endpoints: []))
        try await enforcer.apply(.connecting(resolvers: ["192.0.2.53"], endpoints: ["192.0.2.1:51820"]))
        try await enforcer.apply(.connected(interfaceName: "utun7", endpoints: ["192.0.2.1:51820"]))
        let count = await system.calls.count
        #expect(count <= 20)
        #expect(await system.liveTokens.count == 1)
        #expect(await system.calls.allSatisfy { $0 != ["-E"] })
        #expect(await enforcer.verification() == .protected)
        if let root = ProcessInfo.processInfo.environment["CLEAN_DEV_BUILDS"] {
            try JSONEncoder().encode(["coldRecoveredReferenceConnect": count])
                .write(to: URL(fileURLWithPath: root).appendingPathComponent("M1-16-cold-pf-count.json"))
        }
    }

    @Test
    func `D8 real PF adapter captive refusal has a typed category and retains blocking`() async throws {
        let h = try ControllerHarness(); try await h.install(); await h.ports.setInterfaceName("utun7")
        let journal = DaemonPFTokenJournal(journal: h.journal), system = CompositionPFSystem(
            fault: .none,
            journal: DaemonPFTokenJournal(journal: h.journal),
        )
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        let controller = makeController(h, enforcer: enforcer)
        _ = try await controller.start(profileID: h.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        await system.refuseCaptivePolicy()
        do {
            try await controller.openCaptiveWindow(seconds: 30, connectionUID: 501)
            Issue.record("Captive policy unexpectedly loaded")
        } catch {
            #expect((error as? DaemonFailure)?.kind == .captivePolicyFailed)
        }
        #expect(await enforcer.verification() == .blocked)
        #expect(h.journal.snapshot().captiveWindow == nil)
        await controller.cancelBackgroundWork()
    }

    @Test
    func `supersession decoration retains the base ports refusing repair behaviour`() async throws {
        let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: PFMemoryJournal())
        let base = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
        )
        let admission = SupersessionPolicyAdmission(base: base)
        await #expect(throws: DaemonFailure.pfVerification) {
            _ = try await admission.repairLiveness(existingToken: nil, failure: DaemonFailure.pfVerification)
        }
    }

    /// A cancelled predecessor still rolls back through the real PF port; supersession must never publish a policy failure.
    @Test(arguments: [false, true])
    func `superseding a real-enforcer start rolls back PF without publishing blockingPolicyFailed`(byStart: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.setInterfaceName("utun7")
        let (system, enforcer) = try supersessionEnforcer(harness)
        let gates = SupersessionSteps()
        let admission = SupersessionPolicyAdmission(base: enforcer)
        let controller = makeController(harness, enforcer: enforcer, measurePolicyInVerifier: true, steps: gates, policyPort: admission)
        let log = StatusLog()
        let watcher = log.observe(controller.serviceEvents)
        defer { watcher.cancel() }
        let first = Task {
            try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        }
        await gates.predecessor.wait()
        let successor = Task {
            byStart
                ? try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
                : try await controller.stop(profileID: harness.profile.id, connectionUID: 501)
        }
        while await controller.currentGeneration.rawValue < 2 {
            await Task.yield()
        }
        await gates.predecessor.release()
        await checkSuperseded(first)
        #expect(await admission.slotRefusals.isEmpty)
        if byStart {
            await gates.checkRollback(harness, enforcer: enforcer)
            #expect(await system.liveTokens.count == 1)
        }
        let winner = try await successor.value
        #expect(await admission.repairCalls == 0)
        #expect(await admission.slotRefusals.isEmpty)
        #expect(await admission.cancelledRollbackAdmissions > 0)
        #expect(await system.liveTokens.count == (byStart ? 1 : 0))
        let finalPhase: TunnelPhase = byStart ? .active(winner) : .idle
        try await waitForCondition { await log.phases.last == finalPhase }
        watcher.cancel()
        await watcher.value
        await checkSupersessionResult(
            harness,
            controller: controller,
            enforcer: enforcer,
            log: log,
            winner: winner,
            byStart: byStart,
            finalPhase: finalPhase,
        )
    }

    private func supersessionEnforcer(_ harness: ControllerHarness) throws -> (CompositionPFSystem, PolicyEnforcer) {
        let journal = DaemonPFTokenJournal(journal: harness.journal)
        let system = CompositionPFSystem(fault: .none, journal: journal)
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501), canaryProbe: { await system.probe() },
        )
        return (system, enforcer)
    }

    private func checkSuperseded(_ first: Task<Generation, any Error>) async {
        do {
            _ = try await first.value
            Issue.record("Superseded start unexpectedly succeeded")
        } catch { #expect((error as? DaemonFailure)?.kind == .controllerSuperseded) }
    }

    private func checkSupersessionResult(
        _ harness: ControllerHarness, controller: TunnelController, enforcer: PolicyEnforcer, log: StatusLog,
        winner: Generation, byStart: Bool, finalPhase: TunnelPhase,
    ) async {
        let reasons = await log.reasons
        #expect(!reasons.contains(.blockingPolicyFailed), "reasons=\(reasons)")
        #expect(await controller.status.recoveryFailureReason == nil)
        #expect(await controller.status.phase == finalPhase)
        #expect(await enforcer.verification() == (byStart ? .protected : .unprotected))
        #expect(harness.journal.snapshot().resources.map(\.generation) == (byStart ? [winner] : []))
        let undone = harness.journal.snapshot().entries.filter { $0.generation.rawValue == 1 && $0.action == .undo }
        #expect(!undone.isEmpty)
    }
}

private actor StatusLog {
    var reasons: [RecoveryFailureReason?] = []
    var phases: [TunnelPhase] = []
    func add(_ status: TunnelStatus) {
        reasons.append(status.recoveryFailureReason)
        phases.append(status.phase)
    }

    nonisolated func observe(_ events: AsyncStream<DaemonServiceEvent>) -> Task<Void, Never> {
        Task {
            for await event in events {
                if case let .status(status) = event.event {
                    await self.add(status)
                }
            }
        }
    }
}

private struct SupersessionSteps: DaemonStepObserving {
    let predecessor = StepGate(point: .verify)
    let successor = StepGate(point: .validateSecrets)

    func before(_ step: DaemonStep, generation: Generation) async throws {
        if generation.rawValue == 1 {
            try await predecessor.before(step, generation: generation)
        } else {
            try await successor.before(step, generation: generation)
        }
    }

    func checkRollback(_ harness: ControllerHarness, enforcer: PolicyEnforcer) async {
        await successor.wait()
        #expect(await enforcer.current() == .error)
        #expect(await enforcer.verification() == .blocked)
        #expect(harness.journal.snapshot().resources.isEmpty)
        #expect(harness.trace.calls.filter { $0 == "engine.shutdown" }.count == 1)
        await successor.release()
    }
}
