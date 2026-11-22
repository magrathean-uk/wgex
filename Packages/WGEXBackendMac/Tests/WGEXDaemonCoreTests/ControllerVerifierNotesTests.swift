// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXTesting

@Suite(.timeLimit(.minutes(1)))
private struct ControllerVerifierNotesTests {
    @Test
    func `reservation failure retires the engine and publishes unknown protection`() async throws {
        let faults = FaultInjector()
        let harness = try ControllerHarness(journalTransform: { AllocationJournal(base: $0, faults: faults) })
        try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        let epoch = try await harness.start()
        faults.arm("allocate", error: DaemonFailure.journalExhausted)
        await harness.controller.consume(.engine(.deviceClosed(.tunReadError)), generation: epoch)
        #expect(await engine.isShutDown)
        #expect(await harness.controller.engines.isEmpty)
        #expect(await harness.controller.needsRecovery)
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: false, needsSecrets: false))
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test
    func `ordinary failures do not request an extra policy verification`() async throws {
        let harness = try ControllerHarness()
        _ = await harness.controller.failStart(HostTestError.injected, generation: .initial)
        #expect(await harness.ports.canaryChecks == 1) // Only undo's blocking transition; disconnected needs no canary.
    }

    @Test
    func `death after stop reserves its generation still completes teardown`() async throws {
        let gate = StepGate(point: .engineDown)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        let active = try await harness.start()
        let stop = Task { try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid) }
        await gate.wait()
        #expect(await harness.controller.currentGeneration != active)
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        await gate.release()
        _ = try await stop.value
        #expect(await engine.isShutDown)
        #expect(await harness.controller.engines.isEmpty)
        #expect(await harness.controller.status.phase == .idle)
        #expect(await harness.ports.policy == .disconnected)
    }

    @Test
    func `rollback accepts a device that is already down through closure`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        let epoch = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        try await harness.controller.undo(epoch)
        #expect(await engine.isShutDown)
        #expect(await harness.controller.engines.isEmpty)
        #expect(harness.journal.snapshot().resources.isEmpty)
    }

    @Test
    func `fake lifecycle stream is observed before a gated start configures the engine`() async throws {
        let gate = StepGate(point: .configureEngine)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        let start = Task { try await harness.start() }
        await gate.wait()
        let epoch = await harness.controller.currentGeneration
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        while await harness.controller.currentGeneration == epoch, !Task.isCancelled {
            await Task.yield()
        }
        #expect(await harness.controller.currentGeneration != epoch)
        await gate.release()
        _ = await start.result
        while await harness.controller.operation != nil, !Task.isCancelled {
            await Task.yield()
        }
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
        #expect(await engine.isShutDown)
        #expect(await !engine.calls.contains(.up))
    }

    @Test
    func `direct device closure has the same wire error and status category`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        let faults = FaultInjector(); faults.arm("setConfiguration", error: EngineError.deviceClosed)
        let engine = FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)), faults: faults)
        await harness.ports.useEngine(engine)
        #expect(try await fixture.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .profileRevision(1))
        var wire = try ControllerHarness.bundle().wireBytes().withUnsafeBytes { Data($0) }
        defer { wire.resetBytes(in: 0 ..< wire.count) }
        let reply = try await fixture.call(.startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: true), secrets: wire)
        #expect(reply == .error(.tunnel(.engine(code: -9))))
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
    }
}

private struct AllocationJournal: DaemonJournalling {
    let base: DaemonJournal
    let faults: FaultInjector
    func snapshot() -> DaemonJournalDocument {
        base.snapshot()
    }

    func allocate(intent: TunnelIntent?, deletingSecretsOf: UUID?) throws -> Generation {
        if let error = faults.fault(at: "allocate", as: DaemonFailure.self) {
            throw error
        }
        return try base.allocate(intent: intent, deletingSecretsOf: deletingSecretsOf)
    }

    func mutate(generation: Generation?, _ body: (inout DaemonJournalDocument) throws -> Void) throws {
        try base.mutate(generation: generation, body)
    }
}
