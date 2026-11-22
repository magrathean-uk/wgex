// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXEngineInterface
import WGEXTesting

@Suite(.timeLimit(.minutes(1)))
private struct ControllerEngineLifecycleTests {
    @Test
    func `engine death closes a captive exception before blocking`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
        #expect(harness.journal.snapshot().captiveWindow != nil)
        await harness.controller.consume(.engine(.deviceClosed(.tunReadError)), generation: epoch)
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(await harness.ports.modifiers.last?.captiveWindow == nil)
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
    }

    @Test(arguments: [false, true])
    func `rejected endpoint changes retain the previous live selection`(refresh: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let faults = FaultInjector()
        let engine = FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)), faults: faults)
        await harness.ports.useEngine(engine)
        let epoch = try await harness.start()
        let previous = await harness.controller.selectedEndpoints
        faults.arm("updateEndpoints", error: EngineError.config)
        if refresh {
            await harness.ports.setAnswers(["192.0.2.99"])
            await #expect(throws: EngineError.config) { try await harness.controller.refreshEndpoints(generation: epoch) }
        } else {
            harness.clock.advance(.seconds(10))
            await #expect(throws: EngineError.config) { try await harness.controller.tick() }
        }
        await harness.controller.consume(.engine(.configRestored), generation: epoch)
        #expect(await harness.controller.selectedEndpoints == previous)
        #expect(await !engine.isShutDown)
        #expect(await engine.isUp)
    }

    @Test
    func `the fake engine lifecycle stream reaches the controller`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        _ = try await harness.start()
        var updates = await harness.controller.statusUpdates().makeAsyncIterator()
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        while let status = await updates.next() {
            if case .failed = status.phase {
                break
            }
        }
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
        #expect(await engine.isShutDown)
    }

    @Test(arguments: [PFVerificationStatus.rulesVerified, .unknown, .protected])
    func `unverified blocking never claims blocked`(_ verification: PFVerificationStatus) async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        await harness.ports.reportVerification(verification)
        await harness.controller.consume(.engine(.deviceClosed(.unknown)), generation: epoch)
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: false, needsSecrets: false))
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test
    func `direct rebind device death retires the handle`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let faults = FaultInjector()
        let engine = FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)), faults: faults)
        await harness.ports.useEngine(engine)
        _ = try await harness.start()
        faults.arm("bumpSockets", error: EngineError.deviceClosed)
        await #expect(throws: EngineError.deviceClosed) { try await harness.controller.pathChanged(
            ControllerHarness.underlay,
            satisfied: true,
        ) }
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
        #expect(await engine.isShutDown)
        #expect(await !engine.calls.contains(.down))
    }

    @Test(arguments: [
        EngineLifecycleEvent.deviceClosed(.tunReadError),
        .deviceClosed(.configurationRejected),
        .deviceClosed(.unknown),
        .socketsBumped(ok: false),
    ])
    func `fatal events block and retire the handle`(_ event: EngineLifecycleEvent) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        let epoch = try await harness.start()
        await harness.controller.consume(.engine(event), generation: epoch)
        let code: Int32 = event == .socketsBumped(ok: false) ? -5 : -9
        #expect(await harness.controller.status.phase == .failed(.engine(code: code), blockedByPolicy: true, needsSecrets: false))
        #expect(await harness.controller.status.protection == .blocked)
        #expect(await harness.ports.policy == .error)
        #expect(await engine.isShutDown)
        #expect(await engine.calls.filter { $0 == .shutdown }.count == 1)
        #expect(await !engine.calls.contains(.down))
        #expect(await harness.controller.currentGeneration != epoch)
        #expect(await harness.controller.engines.isEmpty)
    }

    @Test
    func `blocking failure publishes unknown and still retires the handle`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        harness.trace.fail(at: "pf.error")
        await harness.controller.consume(.engine(.deviceClosed(.tunReadError)), generation: epoch)
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: false, needsSecrets: false))
        #expect(await harness.controller.status.protection == .unknown)
        #expect(harness.trace.calls.contains("engine.shutdown"))
        #expect(!harness.trace.calls.contains("engine.down"))
    }

    @Test
    func `old death and health events cannot fail or revive a replacement`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let old = try await harness.start()
        await harness.controller.consume(.engine(.deviceClosed(.tunReadError)), generation: old)
        let fresh = try await harness.start()
        let before = await harness.controller.status
        await harness.controller.consume(.engine(.deviceClosed(.configurationRejected)), generation: old)
        await harness.controller.consume(.engine(.socketsBumped(ok: false)), generation: old)
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: old)
        #expect(await harness.controller.status == before)
        #expect(await harness.controller.status.phase == .active(fresh))
    }

    @Test
    func `restored config and successful bump preserve the live configuration`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        let before = await harness.controller.status
        let calls = harness.trace.calls
        await harness.controller.consume(.engine(.configRestored), generation: epoch)
        await harness.controller.consume(.engine(.socketsBumped(ok: true)), generation: epoch)
        #expect(await harness.controller.status == before)
        #expect(harness.trace.calls == calls)
    }

    @Test
    func `death fences a suspended start before it can publish active`() async throws {
        let gate = StepGate(point: .installRoutes)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let start = Task { try await harness.start() }
        await gate.wait()
        let epoch = await harness.controller.currentGeneration
        let death = Task { await harness.controller.consume(.engine(.deviceClosed(.tunReadError)), generation: epoch) }
        while await harness.controller.currentGeneration == epoch {
            await Task.yield()
        }
        #expect(await harness.controller.status.protection == .unknown)
        await gate.release()
        _ = await start.result; await death.value
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
        #expect(!harness.trace.calls.contains("pf.connected"))
        #expect(!harness.trace.calls.contains("engine.down"))
    }

    @Test
    func `synchronous device death uses the same failure path`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let faults = FaultInjector(); faults.arm("setConfiguration", error: EngineError.deviceClosed)
        let engine = FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)), faults: faults)
        await harness.ports.useEngine(engine)
        await #expect(throws: EngineError.deviceClosed) { _ = try await harness.start() }
        #expect(await harness.controller.status.phase == .failed(.engine(code: -9), blockedByPolicy: true, needsSecrets: false))
        #expect(await engine.calls.filter { $0 == .shutdown }.count == 1)
        #expect(await !engine.calls.contains(.down))
    }
}
