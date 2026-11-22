// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct StartupControlTests {
    @Test
    func `fresh orderly stop does not install a blocking policy`() async throws {
        let harness = try ControllerHarness()
        try await harness.controller.shutdownCleanly()
        #expect(harness.trace.calls.isEmpty)
        #expect(harness.journal.snapshot().cleanShutdownAt != nil)
    }

    @Test
    func `stop drains a suspended failure policy and cannot be reblocked by its continuation`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        let controller = try harness.replacementController(), gate = StepGate(point: .reconcileBlocking)
        await harness.ports.suspend(using: gate)
        let failure = Task { try await controller.recoveryFailed(.resolverUnavailable) }
        await gate.wait()
        let prior = await controller.currentGeneration
        let stop = Task { try await controller.stop(profileID: harness.profile.id, connectionUID: 501) }
        for _ in 0 ..< 2000 {
            if await controller.currentGeneration > prior {
                break
            }
            await Task.yield()
        }
        #expect(await controller.currentGeneration > prior)
        await gate.release()
        await #expect(throws: CancellationError.self) { try await failure.value }
        _ = try await stop.value
        #expect(await controller.status.protection == .unprotected)
        #expect(harness.trace.calls.last == "pf.release")
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent == nil)
    }

    @Test
    func `stop during startup drains cancellation and cannot publish a late recovery failure`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        let controller = try harness.replacementController()
        let gate = StepGate(point: .createEngine)
        await harness.ports.suspend(using: gate)
        let recovering = Task { try await controller.reconcileAtStartup() }
        await gate.wait()
        let stopping = Task { try await controller.stop(profileID: harness.profile.id, connectionUID: 501) }
        // The stop reserves a new generation before draining the blocked predecessor.
        for _ in 0 ..< 1000 {
            if await controller.currentGeneration > harness.journal.snapshot().generation.next() {
                break
            }
            await Task.yield()
        }
        #expect(await controller.currentGeneration > harness.journal.snapshot().generation.next())
        await gate.release()
        _ = await recovering.result
        _ = try await stopping.value
        #expect(await controller.status.protection == .unprotected)
        #expect(await controller.status.recoveryFailureReason == nil)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent == nil)
    }

    @Test
    func `resolver failure is classified while the listener can read status and stop the persisted intent`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        try harness.journal.mutate(generation: nil) { $0.lastGoodAddresses = [:] }
        let controller = try harness.replacementController()
        harness.trace.fail(at: "resolver.resolve")
        await #expect(throws: DaemonFailure.startup(.resolverUnavailable)) { try await controller.reconcileAtStartup() }
        #expect(await controller.status.recoveryFailureReason == .resolverUnavailable)
        #expect(await controller.status.protection == .blocked)
        let fixture = CompositionFixture(harness: harness, controller: controller)
        try await fixture.connect()
        #expect(try await fixture.call(.status).statusProtection == controller.status.protection)
        #expect(try await fixture.call(.stopCurrent(reason: .userRequested)) == .ok)
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(document.intent == nil)
        #expect(document.pfToken == nil)
        #expect(await controller.status.protection == .unprotected)
    }

    @Test
    func `recovery settings permit tightening without secure install and refuse loosening`() async throws {
        let harness = try ControllerHarness(secureInstall: UnavailableSecureInstall())
        try await harness.controller.recoveryFailed(.secureInstallRequired)
        var settings = MacGlobalSettings.defaults; settings.lockdown = true; settings.allowLAN = false
        try await harness.controller.setGlobalSettings(settings, connectionUID: 501)
        #expect(harness.journal.snapshot().settings == settings)
        #expect(await harness.controller.status.protection == .blocked)
        await #expect(throws: DaemonError.recovering) { try await harness.controller.setGlobalSettings(.defaults, connectionUID: 501) }
    }

    @Test
    func `lockdown only shutdown retains the reference and the next start observes and clears the clean marker`() async throws {
        let harness = try ControllerHarness()
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        try await harness.controller.setGlobalSettings(settings)
        try await harness.controller.shutdownCleanly()
        #expect(harness.journal.snapshot().pfToken != nil)
        #expect(harness.journal.snapshot().cleanShutdownAt != nil)
        let replacement = try harness.replacementController()
        #expect(replacement.previousShutdownWasClean)
        try await replacement.reconcileAtStartup()
        #expect(try DaemonJournal(directory: harness.directory).snapshot().cleanShutdownAt == nil)
        #expect(await replacement.status.protection == .blocked)
    }
}
