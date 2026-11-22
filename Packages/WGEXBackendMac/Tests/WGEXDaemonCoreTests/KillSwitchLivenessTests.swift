// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// Scripted kernel state; fixed synthetic replies only. Never constructs a Process or a socket.
private actor LivenessPFSystem: PacketFilterSystem {
    fileprivate enum Fault: Sendable, CaseIterable { case disabled, released, changedAnchor, noStockAnchor, noCanary }
    private var fault: Fault?
    private var text = ""
    private var counter: UInt64 = 0
    private var enabled = true
    private var reference: String?
    private var nextToken = 99
    fileprivate private(set) var calls: [[String]] = []
    fileprivate func setFault(_ fault: Fault) {
        if fault == .released {
            reference = nil
        }
        self.fault = fault; if fault == .disabled || fault == .released {
            enabled = false
        }
    }

    fileprivate func probe() {
        if enabled, fault != .noCanary, fault != .noStockAnchor {
            counter += 1
        }
    }

    fileprivate func clearFault() {
        fault = nil
    }

    func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        try beforeExec(123)
        return try run(arguments: ["-E"], input: Data(), deadline: deadline)
    }

    fileprivate func run(arguments: [String], input: Data, deadline: TimeInterval) throws -> PFCommandResult {
        calls.append(arguments)
        if arguments.contains("-T"), arguments.last == "show" {
            return PFCommandResult(stdout: pfTableOutput(text))
        }
        switch arguments {
        case ["-E"]:
            let token = String(nextToken)
            enabled = true; reference = token; nextToken += 1
            if fault == .released {
                fault = nil
            }
            return try PFCommandResult(stderr: PFTranscripts.read("enable", token: token))
        case ["-e"]: enabled = true; fault = nil
        case ["-s", "References"]:
            return try PFCommandResult(
                stdout: PFTranscripts.references(reference.map { [.init(pid: 123, token: $0)] } ?? []),
                stderr: PFTranscripts.preamble,
            )
        case ["-s", "rules"]: return try PFCommandResult(
                stdout: fault == .noStockAnchor ? "" : PFTranscripts.stdout("rules"),
                stderr: PFTranscripts.preamble,
            )
        case ["-a", "com.apple", "-s", "Anchors", "-v"]: return try PFCommandResult(
                stdout: PFTranscripts.stdout("anchors"),
                stderr: PFTranscripts.preamble,
            )
        case ["-o", "none", "-a", "com.apple/wgex", "-f", "-"]:
            text = String(decoding: input, as: UTF8.self); counter = 0
            if fault == .changedAnchor {
                fault = nil
            }
        default: return try readback(arguments)
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }

    private func readback(_ arguments: [String]) throws -> PFCommandResult {
        switch arguments {
        case ["-s", "info"]: return try PFCommandResult(stdout: PFTranscripts.enabledInfo(enabled), stderr: PFTranscripts.preamble)
        case ["-a", "com.apple/wgex", "-sr"]: return PFCommandResult(
                stdout: fault == .changedAnchor ? "pass quick all\n" : text,
                stderr: PFTranscripts.preamble,
            )
        case ["-a", "com.apple/wgex", "-vsr"]:
            return PFCommandResult(
                stdout: verbosePF(fault == .changedAnchor ? "pass quick all\n" : text, counter: UInt64(counter)),
                stderr: PFTranscripts.preamble,
            )
        default: break
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }
}

private struct LivenessEngineVerifier: ProtectionVerifying {
    fileprivate func verify(_ expectation: ProtectionExpectation) async throws {
        _ = try await expectation.engine.statistics()
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct KillSwitchLivenessTests {
    @Test
    func `external PF disable uses macOS 26 readback and repairs without allocating another reference`() async throws {
        let system = LivenessPFSystem(), harness = try ControllerHarness()
        await harness.ports.setInterfaceName("utun7")
        let controller = try activeController(harness, system: system)
        try await harness.install()
        _ = try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        let token = harness.journal.snapshot().pfToken
        var observations = await controller.statusUpdates().makeAsyncIterator()
        _ = await observations.next()
        await system.setFault(.disabled)
        try await controller.networkChanged(trigger: .route)
        #expect(await observations.next()?.protection == .unknown)
        #expect(await controller.status.protection == .protected)
        #expect(harness.journal.snapshot().pfToken == token)
        #expect(await system.calls.filter { $0 == ["-E"] }.count == 1)
        #expect(await system.calls.filter { $0 == ["-e"] }.count == 1)
        #expect(try PFTranscripts.enabledInfo(false).contains("Disabled"))
    }

    @Test
    func `a PF liveness failure round trip publishes failed reasserting active`() async throws {
        let system = LivenessPFSystem(), h = try ControllerHarness()
        await h.ports.setInterfaceName("utun7")
        let controller = try activeController(h, system: system)
        try await h.install()
        _ = try await controller.start(profileID: h.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        await system.setFault(.noCanary)
        await #expect(throws: (any Error).self) { try await controller.networkChanged(trigger: .buildChanged) }
        let updates = await controller.statusUpdates()
        let phases = Task { () -> [String] in
            var seen: [String] = []
            for await status in updates {
                switch status.phase {
                case .failed: seen.append("failed")
                case .reasserting: seen.append("reasserting")
                case .active: seen.append("active"); return seen
                default: break
                }
            }
            return seen
        }
        await system.clearFault()
        h.clock.advance(.seconds(5)); try await controller.tick()
        let seen = await phases.value
        #expect(seen.first == "failed")
        #expect(try #require(seen.firstIndex(of: "reasserting")) < #require(seen.firstIndex(of: "active")))
        #expect(await controller.status.protection == .protected)
    }

    private func activeController(_ h: ControllerHarness, system: LivenessPFSystem) throws -> TunnelController {
        let runner = PFCtl(system: system)
        let enforcer = try PolicyEnforcer(
            runner: runner,
            journal: DaemonPFTokenJournal(journal: h.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        return TunnelController(
            registry: h.registry,
            secureInstall: VerifiedSecureInstall(),
            journal: h.journal,
            secrets: h.store,
            ports: DaemonPorts(
                engineFactory: h.ports,
                routes: h.ports,
                dns: h.ports,
                policy: PolicyLivenessAdapter(
                    policy: enforcer,
                    runner: runner,
                ),
                resolver: h.ports,
                device: h.ports,
                verifier: LivenessEngineVerifier(),
                reality: h.ports,
            ),
            underlay: .init(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"]),
            clock: h.clock,
        )
    }

    @Test
    func `recovery heartbeat repairs external release and disable during long startup backoff`() async throws {
        let system = LivenessPFSystem(), harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) { $0.settings.lockdown = true }
        let controller = try recoveryController(harness, system: system)
        let runtime = DaemonRuntime(clock: harness.clock)
        let composition = DaemonComposition(
            controller: controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            statusJournal: StatusPublicationJournal(directory: harness.directory),
        )
        var sleeps = harness.clock.sleeps.makeAsyncIterator()
        await composition.run(runtime: runtime, startListener: {}, startMonitors: {})
        _ = await sleeps.next(); _ = await sleeps.next()
        harness.clock.advance(.seconds(5))
        while await sleeps.next() != .seconds(15) {}
        harness.clock.advance(.seconds(15))
        while await sleeps.next() != .seconds(60) {}
        while !harness.clock.pendingSleeps.contains(.seconds(5)) {
            _ = await sleeps.next()
        }
        var updates = await controller.statusUpdates().makeAsyncIterator()
        _ = await updates.next()
        await system.setFault(.released)
        harness.clock.advance(.seconds(5))
        var unknown = false
        while let status = await updates.next() {
            unknown = unknown || status.protection == .unknown
            if status.protection == .blocked, harness.journal.snapshot().pfToken == "100" {
                break
            }
        }
        #expect(unknown)
        #expect(await controller.status.recoveryFailureReason == .secureInstallRequired)
        #expect(harness.journal.snapshot().pfToken == "100")
        #expect(await system.calls.filter { $0 == ["-E"] }.count == 2)
        while await sleeps.next() != .seconds(5) {}
        await system.setFault(.disabled)
        harness.clock.advance(.seconds(5))
        while let status = await updates.next() {
            if status.protection == .blocked, await system.calls.contains(["-e"]) {
                break
            }
        }
        #expect(await system.calls.contains(["-e"]))
        #expect(await controller.status.protection == .blocked)
        #expect(await system.calls.filter { $0 == ["-E"] }.count == 2)
        await runtime.stop()
    }

    private func recoveryController(_ harness: ControllerHarness, system: LivenessPFSystem) throws -> TunnelController {
        let runner = PFCtl(system: system)
        let enforcer = try PolicyEnforcer(
            runner: runner,
            journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: { await system.probe() },
        )
        return TunnelController(
            registry: harness.registry,
            journal: harness.journal,
            secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: harness.ports,
                routes: harness.ports,
                dns: harness.ports,
                policy: PolicyLivenessAdapter(policy: enforcer, runner: runner),
                resolver: harness.ports,
                device: harness.ports,
                verifier: harness.ports,
                reality: harness.ports,
            ),
            underlay: UnderlaySnapshot(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"]),
        )
    }

    @Test
    func `distinct IPv6 underlay state kills stay interface scoped`() async throws {
        let harness = try NetworkPortHarness(), system = LivenessPFSystem()
        let enforcer = try PolicyEnforcer(
            runner: PFCtl(system: system), journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501), canaryProbe: { await system.probe() },
        )
        try await enforcer.setModifiers(PolicyModifiers(
            allowLAN: false, captiveWindow: nil, consoleUID: 501,
            underlay: UnderlaySnapshot(
                v4: 4, v6: 6, resolvers: [], interfaceNames: ["en0", "en1"], interfaceV4Name: "en0", interfaceV6Name: "en1",
            ),
        ))
        try await enforcer.apply(.lockdown)
        #expect(await system.calls.filter { $0 == ["-i", "en0", "-F", "states"] }.count == 1)
        #expect(await system.calls.filter { $0 == ["-i", "en1", "-F", "states"] }.count == 1)
        #expect(await !system.calls.contains(["-F", "states"]))
    }

    @Test(arguments: LivenessPFSystem.Fault.allCases)
    func `liveness publishes unknown then repairs or retains cannot enforce copy`(fault: LivenessPFSystem.Fault) async throws {
        let system = LivenessPFSystem()
        let harness = try ControllerHarness()
        await harness.ports.setInterfaceName("utun7")
        let runner = PFCtl(system: system)
        let enforcer = try PolicyEnforcer(
            runner: runner, journal: DaemonPFTokenJournal(journal: harness.journal),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501), canaryProbe: { await system.probe() },
        )
        let policy = PolicyLivenessAdapter(policy: enforcer, runner: runner)
        let controller = TunnelController(
            registry: harness.registry, secureInstall: VerifiedSecureInstall(), journal: harness.journal, secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: harness.ports, routes: harness.ports, dns: harness.ports, policy: policy,
                resolver: harness.ports, device: harness.ports, verifier: LivenessEngineVerifier(), reality: harness.ports,
            ),
            underlay: UnderlaySnapshot(v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["en0"]), clock: harness.clock,
        )
        try await harness.install()
        _ = try await controller.start(profileID: harness.profile.id, connectionUID: 501, secrets: ControllerHarness.bundle())
        var events = await controller.statusUpdates().makeAsyncIterator()
        _ = await events.next()
        let token = harness.journal.snapshot().pfToken
        await system.setFault(fault)
        if fault == .disabled || fault == .changedAnchor || fault == .released {
            try await controller.networkChanged(trigger: .route)
            #expect(await controller.status.protection == .protected)
            #expect(harness.journal.snapshot().pfToken == (fault == .released ? "100" : token))
        } else {
            await #expect(throws: (any Error).self) { try await controller.networkChanged(trigger: .buildChanged) }
            #expect(await controller.status.protection == .unknown)
            #expect(await controller.protectionFailureReason?.contains("Restart your Mac") == true)
        }
        #expect(await events.next()?.protection == .unknown)
        #expect(await system.calls.filter { $0 == ["-E"] }.count == (fault == .released ? 2 : 1))
        #expect(await system.calls.contains(["-e"]) == (fault == .disabled))
    }
}
