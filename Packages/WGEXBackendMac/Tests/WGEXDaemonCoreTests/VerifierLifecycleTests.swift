// SPDX-License-Identifier: MIT
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerifierLifecycleTests {
    @Test
    func `secure repair schedules a measured status without an intent`() async throws {
        let system = FakeSecureInstallSystem(), settings = MacGlobalSettings(
            lockdown: true,
            allowLAN: true,
            captiveWindowSeconds: 300,
            notifications: true,
        )
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        try await harness.controller.setGlobalSettings(settings); try await harness.controller.tick()
        system.state.withLock { $0.entries[1].mode = 0o777 }
        await #expect(throws: DaemonError.secureInstallRequired) { try await harness.controller.tick() }
        var updates = await harness.controller.statusUpdates().makeAsyncIterator()
        let before = await harness.ports.canaryChecks
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        let reply = try await fixture.call(.performSecureInstall)
        guard case let .secureInstall(report) = reply else { Issue.record("Missing repair report"); return }
        #expect(report.state == .verified)
        while let status = await updates.next() {
            if status.protection == .blocked {
                break
            }
        }
        #expect(await harness.ports.canaryChecks > before)
        #expect(await harness.controller.status.recoveryFailureReason == nil)
    }

    @Test
    func `runtime preparation resets failure deduplication for the next attempt`() async throws {
        let harness = try ControllerHarness()
        let revision = await harness.controller.startupControlRevision()
        try await harness.controller.prepareStartupBlocking()
        try await harness.controller.recoveryFailed(.monitorStartFailed, expectedControlID: revision)
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 5)
        try await harness.controller.prepareStartupBlocking()
        try await harness.controller.recoveryFailed(.resolverUnavailable, expectedControlID: revision)
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 4)
    }

    @Test
    func `policy measurement failure on tick reports reason eight`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.ports.reportVerification(.unknown)
        harness.clock.advance(.seconds(5))
        await #expect(throws: DaemonFailure.pfVerification) { try await harness.controller.tick() }
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 8)
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test
    func `PF load errors have a specific controller category`() async throws {
        let harness = try ControllerHarness()
        harness.trace.fail(at: "pf.error")
        let epoch = await harness.controller.currentGeneration
        await #expect(throws: DaemonFailure.controllerPolicyVerificationFailed) {
            try await harness.controller.applyPolicy(.error, generation: epoch)
        }
        #expect(await harness.ports.verification() == .unknown)
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 8)
    }

    @Test
    func `watchdog with no intent requires cleanup while abandoned resources remain`() async throws {
        let gate = StepGate(point: .removeDNS)
        let subject = try ControllerHarness(gate: gate); try await subject.install(); _ = try await subject.start()
        let stop = Task { try await subject.controller.stop(profileID: subject.profile.id, connectionUID: 501) }
        await gate.wait()
        let abandoned = await subject.controller.operation
        for _ in 0 ..< 4000 where !subject.clock.pendingSleeps.contains(.seconds(60)) {
            await Task.yield()
        }
        try #require(subject.clock.pendingSleeps.contains(.seconds(60)))
        subject.clock.advance(.seconds(60)); _ = await stop.result
        #expect(await subject.controller.needsRecovery)
        #expect(subject.journal.snapshot().intent == nil)
        #expect(await subject.controller.status.recoveryFailureReason?.rawValue == 6)
        await gate.release(); _ = await abandoned?.result
        try await subject.controller.tick()
        #expect(subject.journal.snapshot().resources.isEmpty)
        #expect(await subject.controller.engines.isEmpty)
        #expect(await subject.controller.status.protection == .unprotected)
        #expect(await subject.controller.activeProfileID() == nil)
    }
}
