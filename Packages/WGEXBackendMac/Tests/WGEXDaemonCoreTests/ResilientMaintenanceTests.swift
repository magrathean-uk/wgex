// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct ResilientMaintenanceTests {
    @Test(arguments: [0, -1, 3601, Int.max])
    func `invalid settings do not enter maintenance or touch policy`(_ seconds: Int) async throws {
        let harness = try ControllerHarness()
        var settings = MacGlobalSettings.defaults; settings.captiveWindowSeconds = seconds
        await #expect(throws: DaemonFailure.controllerInvalidConfiguration) { try await harness.controller.setGlobalSettings(settings) }
        #expect(harness.trace.calls.isEmpty)
        #expect(harness.journal.snapshot().settings == .defaults)
        #expect(await harness.controller.status == .idle)
    }

    @Test(arguments: [false, true])
    func `maintenance failure derives policy from intent and lockdown`(_ lockdown: Bool) async throws {
        let harness = try ControllerHarness()
        if lockdown {
            var settings = MacGlobalSettings.defaults; settings.lockdown = true
            try await harness.controller.setGlobalSettings(settings)
        }
        await #expect(throws: HostTestError.self) { try await harness.controller.maintenance { _, _ in throw HostTestError.injected } }
        #expect(await harness.ports.policy == (lockdown ? .lockdown : .disconnected))
        #expect(await harness.controller.status.protection == (lockdown ? .blocked : .unprotected))
    }

    @Test(arguments: ["pf.canary", "verify", "routes.install", "dns.apply"])
    func `maintenance failures recover on tick without user action`(_ point: String) async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        harness.trace.fail(at: point)
        await #expect(throws: (any Error).self) { try await harness.controller.networkChanged(trigger: .route) }
        #expect(await harness.controller.status.protection == .blocked)
        #expect(await harness.ports.policy == .error)
        harness.clock.advance(.seconds(5))
        var updates = await harness.controller.statusUpdates().makeAsyncIterator()
        try await harness.controller.tick()
        try #require(await harness.controller.status.phase == .active(epoch))
        #expect(await harness.controller.status.protection == .protected)
        var sawReasserting = false
        while let status = await updates.next() {
            if case .reasserting = status.phase {
                sawReasserting = true
            }
            if case .active = status.phase {
                break
            }
        }
        #expect(sawReasserting)
    }

    @Test(arguments: [PFVerificationStatus.captiveWindow, .rulesVerified, .protected, .unknown])
    func `wrong verification class cannot prove blocking`(_ status: PFVerificationStatus) async throws {
        let harness = try ControllerHarness()
        await harness.ports.reportVerification(status)
        await #expect(throws: (any Error).self) { try await harness.controller.applyPolicy(
            .error,
            generation: harness.controller.currentGeneration,
        ) }
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test(arguments: [
        DaemonStep.stopBlocking,
        .removeDNS,
        .removeRoutes,
        .engineDown,
        .engineShutdown,
        .finalPolicy,
        .releaseToken,
        .stopKillStates,
        .deleteSecrets,
    ])
    func `every stop checkpoint failure still completes all teardown steps`(_ step: DaemonStep) async throws {
        let harness = try ControllerHarness(gate: StepGate(point: step, failing: true))
        try await harness.install(); _ = try await harness.start()
        await #expect(throws: (any Error).self) {
            try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        }
        #expect(await harness.controller.engines.isEmpty)
        #expect(harness.trace.calls.contains("engine.shutdown"))
        #expect(harness.trace.calls.contains("secrets.delete"))
        #expect(harness.trace.calls.contains("dns.remove"))
        #expect(harness.trace.calls.contains("routes.remove"))
        #expect(await harness.ports.policy == .disconnected)
        #expect(await harness.controller.status.protection == .unknown)
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 6)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.status.phase == .idle)
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test(arguments: ["dns.remove", "routes.remove", "engine.down", "pf.disconnecting", "pf.disconnected", "pf.release"])
    func `port failures do not trap explicit stop`(_ point: String) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        harness.trace.fail(at: point)
        await #expect(throws: (any Error).self) {
            try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        }
        #expect(await harness.controller.engines.isEmpty)
        #expect(harness.trace.calls.contains("engine.shutdown"))
        #expect(harness.trace.calls.contains("secrets.delete"))
        #expect(harness.trace.calls.contains("pf.disconnected"))
        #expect(await harness.controller.status.protection == .unknown)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test
    func `captive failure withdraws exception before subsequent restoration`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
        harness.trace.fail(at: "routes.install")
        await #expect(throws: (any Error).self) { try await harness.controller.closeCaptiveWindow() }
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(await harness.ports.modifiers.last?.captiveWindow == nil)
        #expect(await harness.ports.policy == .error)
        harness.clock.advance(.seconds(5)); try await harness.controller.tick()
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test(arguments: [DaemonStep.installRoutes, .createEngine, .connected])
    func `watchdog fences a cancellation insensitive adapter and stop proceeds`(_ step: DaemonStep) async throws {
        let gate = StepGate(point: step)
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.suspend(using: gate)
        let start = Task { try await harness.start() }
        await gate.wait()
        let old = await harness.controller.currentGeneration
        let abandoned = await harness.controller.operation
        for _ in 0 ..< 2000 where !harness.clock.pendingSleeps.contains(.seconds(60)) {
            await Task.yield()
        }
        defer { Task { await gate.release() } }
        try #require(harness.clock.pendingSleeps.contains(.seconds(60)))
        harness.clock.advance(.seconds(60))
        _ = await start.result
        #expect(await harness.controller.currentGeneration != old)
        // Expiry reloads the blocking policy and claims only what the policy port then measures (M1-25).
        #expect(await harness.controller.status.protection == .blocked)
        #expect(await harness.ports.verification() == .blocked)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.engines.isEmpty)
        #expect(await harness.controller.status.protection == .unprotected)
        await gate.release()
        _ = await abandoned?.result
        #expect(await harness.controller.status.phase == .idle)
        #expect(await harness.controller.engines.isEmpty)
        #expect(harness.journal.snapshot().resources.isEmpty)
    }
}
