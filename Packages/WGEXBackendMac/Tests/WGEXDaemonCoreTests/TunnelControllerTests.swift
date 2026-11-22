// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct TunnelControllerTests {
    private static let startSteps: [DaemonStep] = [
        .validateSecrets, .blocking, .resolve, .allowEndpoints, .createEngine, .configureEngine, .engineUp,
        .configureInterface, .installRoutes, .installDNS, .verify, .connected, .killStates, .commit,
    ]
    private static let stopSteps: [DaemonStep] = [
        .stopBlocking, .removeDNS, .removeRoutes, .engineDown, .engineShutdown, .finalPolicy, .releaseToken, .stopKillStates,
        .deleteSecrets,
    ]

    @Test
    func `start commits only after verification and stop replays the seven step contract`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let generation = try await harness.start()
        #expect(generation == .initial)
        #expect(await harness.controller.status.phase == .active(generation))
        let document = harness.journal.snapshot()
        #expect(document.entries.filter { $0.action == .didApply }.map(\.step) == Self.startSteps)
        #expect(document.resources.first?.routes.count == 4)
        #expect(document.resources.first?.dnsKey == "State:/Network/Service/\(harness.profile.id.uuidString)/DNS")
        #expect(await harness.ports.configurations.first?.tun == .createUTun(mtu: 1280))
        let stopped = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(stopped > generation)
        #expect(harness.journal.snapshot().entries.filter { $0.generation == stopped && $0.action == .didApply }.map(\.step) == Self
            .stopSteps)
        #expect(harness.journal.snapshot().resources.isEmpty)
        #expect(harness.journal.snapshot().pfToken == nil)
        #expect(await harness.ports.routeItems.isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        #expect(await harness.controller.status.phase == .idle)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }

    @Test(arguments: startSteps)
    func `every start suspension can fail with reverse undo and retained intent`(point: DaemonStep) async throws {
        let harness = try ControllerHarness(gate: StepGate(point: point, failing: true)); try await harness.install()
        await #expect(throws: HostTestError.self) { _ = try await harness.start() }
        let document = harness.journal.snapshot()
        let applied = document.entries.filter { $0.action == .didApply }.map(\.step)
        let expectedUndo = [DaemonStep.installDNS, .installRoutes, .configureInterface, .engineUp, .createEngine]
            .filter { applied.contains($0) }
        #expect(document.entries.filter { $0.action == .undo }.map(\.step) == expectedUndo)
        #expect(document.resources.isEmpty)
        #expect(document.intent?.profileID == harness.profile.id)
        #expect(await harness.ports.policy == .error)
        #expect(await harness.controller.status.protection == .blocked)
    }

    @Test(arguments: [
        "pf.blocking",
        "resolver.resolve",
        "pf.endpoints",
        "engine.create",
        "engine.configure",
        "engine.up",
        "device.configure",
        "routes.install",
        "dns.apply",
        "verify",
        "pf.connected",
    ])
    func `port failures undo partially installed resources including set configuration failure`(point: String) async throws {
        let harness = try ControllerHarness(); try await harness.install(); harness.trace.fail(at: point)
        await #expect(throws: (any Error).self) { _ = try await harness.start() }
        #expect(await harness.ports.routeItems.isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        #expect(await harness.ports.policy == .error)
        #expect(harness.journal.snapshot().resources.isEmpty)
        if point == "engine.configure" {
            #expect(harness.trace.calls.contains("engine.shutdown"))
        }
        let undo = harness.journal.snapshot().entries.filter { $0.action == .undo }.map(\.step)
        let positions = undo
            .compactMap { [DaemonStep.installDNS, .installRoutes, .configureInterface, .engineUp, .createEngine].firstIndex(of: $0) }
        #expect(positions == positions.sorted())
    }

    @Test(arguments: startSteps)
    func `a CLI start supersedes an app start at every suspension`(point: DaemonStep) async throws {
        let gate = StepGate(point: point)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let app = Task { try await harness.start() }
        await gate.wait()
        let cli = Task { try await harness.start() }
        // Wait for allocation using the actor, without a wall-clock sleep.
        while await harness.controller.currentGeneration.rawValue < 2 {
            await Task.yield()
        }
        await gate.release()
        let winner = try await cli.value
        do { _ = try await app.value; Issue.record("Superseded start unexpectedly succeeded") }
        catch {
            #expect((error as? DaemonFailure)?.kind == .controllerSuperseded)
            #expect(await harness.controller.currentGeneration == winner)
        }
        #expect(await harness.controller.status.phase == .active(winner))
        #expect(harness.journal.snapshot().resources.map(\.generation) == [winner])
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
    }

    @Test(arguments: [DaemonStep.createEngine, .installRoutes, .installDNS, .connected])
    func `late adapter returns are undone before the next generation touches ports`(point: DaemonStep) async throws {
        let gate = StepGate(point: point)
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.suspend(using: gate)
        let old = Task { try await harness.start() }
        await gate.wait()
        let replacement = Task { try await harness.start() }
        while await harness.controller.currentGeneration.rawValue < 2 {
            await Task.yield()
        }
        await gate.release()
        let epoch = try await replacement.value
        do { _ = try await old.value; Issue.record("Old adapter return escaped the generation fence") }
        catch {
            #expect((error as? DaemonFailure)?.kind == .controllerSuperseded)
            #expect(await harness.controller.currentGeneration == epoch)
        }
        #expect(await harness.ports.routeItems.keys.sorted() == [epoch])
        #expect(await harness.ports.dnsItems.keys.sorted() == [epoch])
        #expect(harness.trace.calls.filter { $0 == "engine.shutdown" }.count == 1)
        #expect(await harness.controller.status.phase == .active(epoch))
    }

    @Test(arguments: stopSteps)
    func `a newer start cancels a stop at every suspension`(point: DaemonStep) async throws {
        let gate = StepGate(point: point)
        let harness = try ControllerHarness(gate: gate); try await harness.install(); _ = try await harness.start()
        let stop = Task { try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid) }
        await gate.wait()
        let start = Task { try await harness.start() }
        while await harness.controller.currentGeneration.rawValue < 3 {
            await Task.yield()
        }
        await gate.release()
        let winner = try await start.value
        do { _ = try await stop.value; Issue.record("Superseded stop unexpectedly succeeded") }
        catch {
            #expect((error as? DaemonFailure)?.kind == .controllerSuperseded)
            #expect(await harness.controller.currentGeneration == winner)
        }
        #expect(await harness.controller.status.phase == .active(winner))
    }

    @Test(arguments: startSteps)
    func `explicit disconnect cancels each start suspension and retires secrets`(point: DaemonStep) async throws {
        let gate = StepGate(point: point)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let start = Task { try await harness.start() }
        await gate.wait()
        let stop = Task { try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid) }
        while await harness.controller.currentGeneration.rawValue < 2 {
            await Task.yield()
        }
        await gate.release()
        let epoch = try await stop.value
        do { _ = try await start.value; Issue.record("Cancelled start unexpectedly succeeded") }
        catch {
            #expect((error as? DaemonFailure)?.kind == .controllerSuperseded)
            #expect(await harness.controller.currentGeneration == epoch)
        }
        #expect(await harness.controller.status.phase == .idle)
        #expect(harness.journal.snapshot().intent == nil)
        #expect(harness.journal.snapshot().pendingSecretDeletions.isEmpty)
        #expect(await harness.ports.routeItems.isEmpty)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }

    @Test
    func `rollback identities survive journal history compaction`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let first = try await harness.start()
        try harness.journal.mutate(generation: first) { $0.entries = [] }
        let second = try await harness.start()
        #expect(harness.journal.snapshot().entries.filter { $0.generation == first && $0.action == .undo }.map(\.step) ==
            [.installDNS, .installRoutes, .configureInterface, .engineUp, .createEngine])
        #expect(await harness.controller.status.phase == .active(second))
    }

    @Test
    func `stale mutations and a second intended up profile are rejected without changing generation`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let generation = try await harness.start()
        do {
            try await harness.controller.stop(
                profileID: harness.profile.id,
                connectionUID: ControllerHarness.uid,
                expectedGeneration: .init(rawValue: 0),
            )
            Issue.record("Stale expected generation was accepted")
        } catch {
            #expect((error as? DaemonFailure)?.kind == .controllerStaleGeneration)
        }
        let second = try ControllerHarness.makeProfile()
        try await harness.registry.installProfile(second, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        await #expect(throws: DaemonFailure.controllerAnotherTunnelActive) {
            try await harness.controller.start(profileID: second.id, connectionUID: ControllerHarness.uid)
        }
        #expect(await harness.controller.currentGeneration == generation)
    }

    @Test
    func `authenticated root start preserves the registered owner and does not grant owner only removal`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let epoch = try await harness.controller.start(profileID: harness.profile.id, connectionUID: 0, secrets: ControllerHarness.bundle())
        #expect(harness.journal.snapshot().intent?.ownerUID == ControllerHarness.uid)
        #expect(await harness.controller.status.phase == .active(epoch))
        await #expect(throws: DaemonFailure.registryNotOwner) {
            try await harness.registry.removeProfile(harness.profile.id, purgeSecrets: true, connectionUID: 0)
        }
    }

    @Test(arguments: [StopReason.systemShutdown, .logout, .update])
    func `system stops retain secrets and intended up blocking`(reason: StopReason) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid, reason: reason)
        let bytes = try await harness.store.loadBundle(profileID: harness.profile.id)
        #expect(bytes.count > 32)
        #expect(harness.journal.snapshot().intent != nil)
        #expect(await harness.controller.status.protection == .blocked)
    }
}
