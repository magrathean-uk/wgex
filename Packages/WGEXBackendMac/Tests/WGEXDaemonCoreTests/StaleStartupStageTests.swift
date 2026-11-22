// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25 fix pass 1, B5 and verify A's P1: a startup stage whose watchdog expired may still resume from a
/// cancellation-insensitive adapter read. It must never reserve a boot intent, apply a policy, or hand a start over: its
/// view of the world (settings, intent, control identity) is older than the controller's.
@Suite(.timeLimit(.minutes(1)))
private struct StaleStartupStageTests {
    @Test
    func `a stage 1 that expired parked at the secure-install read reserves no boot intent when it resumes`() async throws {
        let install = ParkingSecureInstall()
        let rig = try await BootRig.make(secureInstall: install, persisted: .bootProfile)
        let harness = rig.harness, controller = rig.controller
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop() }; install.release() }
        await install.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        // The expiry is complete: no intent was persisted, so it reserved a generation for none.
        let expired = await controller.currentGeneration
        #expect(await controller.intended == nil)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent == nil)

        install.release()
        try await waitForCondition { install.returned == 1 }
        // The stale continuation's first actor turn was scheduled by the release; these actor calls queue behind it.
        for _ in 0 ..< 50 {
            _ = await controller.currentGeneration
        }
        #expect(await controller.intended == nil, "the stale stage set the boot intent after the expiry")
        #expect(await controller.currentGeneration == expired, "the stale stage advanced the generation after the expiry")
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent == nil)
        #expect(await controller.startup.bootStart == nil)

        // The runtime's own retry, behind its backoff, is what reserves the boot intent and starts the tunnel.
        harness.clock.advance(.seconds(5))
        try await rig.waitForPhase(\.isActive)
        #expect(await controller.status.protection == .protected)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent?.profileID == harness.profile.id)
    }

    @Test
    func `a stage 1 that expired parked at the policy read never applies disconnected after the user enabled lockdown`() async throws {
        // No intent, no lockdown and no boot profile: reconciliation ends in the branch that settles on `disconnected`.
        let read = PolicyReadGate(.current) { $0.lastJournalEntry(is: .applyIntents, .willApply) }
        let rig = try await BootRig.make(persisted: .none, portsTransform: { $0.gatingPolicy(read) })
        read.bind(rig.harness)
        let harness = rig.harness, controller = rig.controller
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop() }; read.release() }
        await read.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))

        // The user turns lockdown on. The recovery control rotates the control identity and reserves its generation; the
        // runtime's requeued reconciliation then settles on `lockdown`.
        var requested = MacGlobalSettings.defaults; requested.lockdown = true
        let settings = requested
        try await controller.setGlobalSettings(settings, connectionUID: ControllerHarness.uid)
        try await rig.waitForPhase { $0 == .idle }
        try await waitForCondition { await controller.needsRecovery == false }
        #expect(await harness.ports.policy == .lockdown)
        let baseline = harness.trace.calls.count
        let generation = await controller.currentGeneration

        read.release()
        try await waitForCondition { read.returned == 1 }
        for _ in 0 ..< 50 {
            _ = await controller.currentGeneration
        }
        // The stale stage computed `disconnected` before the user's change; it must not apply it, release the token or
        // publish idle/blocked over the lockdown that is in force.
        #expect(harness.trace.calls.dropFirst(baseline).contains("pf.disconnected") == false, "the stale stage loaded disconnected")
        #expect(await harness.ports.policy == .lockdown)
        #expect(await harness.ports.verification() == .blocked)
        #expect(await controller.currentGeneration == generation)
        #expect(await controller.status.protection == .blocked)
        #expect(await controller.settings.lockdown)
        #expect(await harness.ports.token != nil, "the stale stage released the policy token")
    }

    /// M1-29 R2: the secure-install read is the one stage-1 await whose failure branch wrote state (`reconciliationPending`)
    /// before any control-identity check. A stale stage must not flag a healthy tunnel for another reconciliation.
    @Test
    func `a stage 1 that expired parked at the secure-install read sets no reconciliation flag after the tunnel recovered`() async throws {
        let install = ParkingSecureInstall(firstState: .needsAttention(.inspectionFailed))
        let rig = try await BootRig.make(secureInstall: install)
        let harness = rig.harness, controller = rig.controller
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop() }; install.release() }
        await install.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        harness.clock.advance(.seconds(5))
        try await rig.waitForPhase(\.isActive)
        try await waitForCondition { await controller.needsRecovery == false }
        #expect(await controller.status.protection == .protected)
        let generation = await controller.currentGeneration
        let shutdowns = rig.count("engine.shutdown"), creates = rig.count("engine.create")

        // The stale read now comes back with a verdict that is not verified, long after the stage lost its identity.
        install.release()
        try await waitForCondition { install.returned == 1 }
        for _ in 0 ..< 50 {
            _ = await controller.currentGeneration
        }
        #expect(await controller.startup.reconciliationPending == false, "the stale stage flagged a pending reconciliation")
        #expect(await controller.shouldRetryStartup() == false)
        // The next maintenance tick must leave the working tunnel alone.
        try await controller.tick()
        #expect(rig.count("engine.shutdown") == shutdowns, "the next tick tore the active tunnel down")
        #expect(rig.count("engine.create") == creates, "the next tick rebuilt the active tunnel")
        #expect(await controller.currentGeneration == generation)
        #expect(await controller.status.phase.isActive)
    }

    /// M1-29 R6: a stale stage that returns from the engine shutdowns must not leave the shut-down handles in the map.
    @Test
    func `a stage 1 that expired parked in an engine shutdown leaves no shut-down handle in the engine map`() async throws {
        let gate = StepGate(point: .createEngine)
        let rig = try await BootRig.make()
        let harness = rig.harness, controller = rig.controller
        let engine = HostEngine(trace: harness.trace)
        await engine.parkShutdown(using: gate)
        await controller.adopt(engine, generation: controller.currentGeneration)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        #expect(await controller.engines.count == 1)

        await gate.release()
        try await waitForCondition { await engine.shutdownReturns == 1 }
        let cleared = await eventually { await controller.engines.isEmpty }
        #expect(cleared, "the stale stage left a shut-down engine handle in the map")
    }
}
