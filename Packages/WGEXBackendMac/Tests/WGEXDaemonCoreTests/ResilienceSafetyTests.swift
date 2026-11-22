// SPDX-License-Identifier: MIT
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct ResilienceSafetyTests {
    @Test(arguments: [DaemonStep.openCaptive, .closeCaptive, .rotateCandidate, .retryBackoff])
    func `maintenance checkpoint failures withdraw captive permissions and recover`(_ step: DaemonStep) async throws {
        let harness = try ControllerHarness(gate: StepGate(point: step, failing: true))
        try await harness.install()
        if step == .retryBackoff {
            await harness.ports.setAnswers(["192.0.2.1"])
        }
        _ = try await harness.start()
        if step == .closeCaptive {
            try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
            await #expect(throws: (any Error).self) { try await harness.controller.closeCaptiveWindow() }
        } else if step == .openCaptive {
            await #expect(throws: (any Error).self) {
                try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
            }
        } else {
            harness.clock.advance(.seconds(10))
            await #expect(throws: (any Error).self) { try await harness.controller.tick() }
        }
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(await harness.ports.modifiers.last?.captiveWindow == nil)
        #expect(await harness.controller.status.protection == .blocked)
        harness.clock.advance(.seconds(5)); try await harness.controller.tick()
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `maintenance retry waits five fifteen and sixty seconds then heals`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        harness.trace.fail(at: "pf.canary")
        await #expect(throws: (any Error).self) { try await harness.controller.networkChanged(trigger: .route) }
        for delay in [5, 15, 60] {
            let count = harness.trace.calls.count
            harness.clock.advance(.seconds(delay - 1)); try await harness.controller.tick()
            #expect(harness.trace.calls.count == count)
            harness.trace.fail(at: "pf.connected")
            harness.clock.advance(.seconds(1))
            await #expect(throws: (any Error).self) { try await harness.controller.tick() }
            #expect(await harness.controller.status.protection == .blocked)
        }
        harness.clock.advance(.seconds(60)); try await harness.controller.tick()
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `reconcile drains an occupied lifecycle slot instead of rejecting it`() async throws {
        let gate = StepGate(point: .installRoutes)
        let harness = try ControllerHarness(gate: gate); try await harness.install()
        let start = Task { try await harness.start() }; await gate.wait()
        let reconcile = Task { try await harness.controller.reconcileAtStartup() }
        await gate.release(); _ = try await start.value; try await reconcile.value
        #expect(await !harness.controller.needsRecovery)
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `secure install regression preserves blocking and reports unknown while stop remains available`() async throws {
        let system = FakeSecureInstallSystem()
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        try await harness.install(); _ = try await harness.start()
        system.state.withLock { $0.entries[1].mode = 0o777 }
        await #expect(throws: DaemonError.secureInstallRequired) { try await harness.controller.tick() }
        #expect(await harness.controller.status.protection == .unknown)
        #expect(await harness.ports.policy == .error)
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        try await harness.controller.setGlobalSettings(settings)
        #expect(await harness.ports.policy == .lockdown)
        #expect(await harness.controller.status.protection == .unknown)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.engines.isEmpty)
        #expect(await harness.ports.policy == .lockdown)
    }

    @Test
    func `captive close withdraws exception even when secure install regresses`() async throws {
        let system = FakeSecureInstallSystem()
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
        system.state.withLock { $0.entries[1].mode = 0o777 }
        await #expect(throws: DaemonError.secureInstallRequired) { try await harness.controller.closeCaptiveWindow() }
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(await harness.ports.policy == .error)
        #expect(await harness.ports.modifiers.last?.captiveWindow == nil)
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test(arguments: ["pf.disconnecting", "reality.inspect", "engine.down", "pf.disconnected", "pf.release"])
    func `an incomplete recovery stop can be retried after its intent was cleared`(_ point: String) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.recoveryFailed(.profileUnavailable)
        harness.trace.fail(at: point)
        await #expect(throws: (any Error).self) {
            try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        }
        #expect(await harness.controller.engines.isEmpty)
        #expect(await harness.controller.status.protection == .unknown)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.status.phase == .idle)
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test
    func `stop current retries an incomplete teardown after intent was cleared`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        try await harness.controller.recoveryFailed(.profileUnavailable)
        harness.trace.fail(at: "engine.down")
        let first = try await fixture.call(.stopCurrent(reason: .userRequested))
        #expect(first != .ok)
        #expect(await harness.controller.status.protection == .unknown)
        #expect(try await fixture.call(.stopCurrent(reason: .userRequested)) == .ok)
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test
    func `repair notification does not await a suspended recovery attempt`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .inspectReality)
        await harness.controller.setStartupRetry {
            try? await gate.before(.inspectReality, generation: .initial)
        }
        try await harness.controller.repairRegistration { _ in }
        await gate.wait()
        #expect(await harness.controller.operation == nil)
        await gate.release()
    }

    @Test
    func `stop never publishes blocked before its blocking policy is measured`() async throws {
        let gate = StepGate(point: .stopBlocking)
        let harness = try ControllerHarness(gate: gate); try await harness.install(); _ = try await harness.start()
        let stop = Task { try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid) }
        await gate.wait()
        #expect(await harness.controller.status.protection == .unknown)
        await gate.release(); _ = try await stop.value
    }
}
