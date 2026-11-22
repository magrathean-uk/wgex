// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25: the boot reconnect survives a slow boot. The 60 s watchdog bounds reconciliation and the boot-intent start
/// separately, expiry publishes only what was measured, and the requeue after expiry backs off.
@Suite(.timeLimit(.minutes(1)))
private struct BootStartBudgetTests {
    @Test
    func `reconciliation time is not charged to the boot start`() async throws {
        let reconciliation = StepGate(point: .validateSecrets), start = StepGate(point: .createEngine)
        let rig = try await BootRig.make(secureInstall: ReconciliationGate(gate: reconciliation))
        let harness = rig.harness
        await harness.ports.suspend(using: start)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await reconciliation.release(); await start.release() } }
        await reconciliation.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(59))
        await reconciliation.release()
        await start.wait()
        // The start's own 60 s deadline registers once the hand-over is done: advance only after it is there, or the
        // deadline would be measured from a later "now" and the assertion below would see 60 s, not 1 s.
        try await rig.waitForPendingSleep(.seconds(60))
        // 118 s after the reboot, but only 59 s into the start: nothing may have expired.
        harness.clock.advance(.seconds(59))
        // The start's own watchdog has one second left; a single watchdog over both stages would have fired at 60 s. The
        // list is read straight after the advance: a deadline that fired would already have left it.
        #expect(harness.clock.pendingSleeps == [.seconds(1)])
        #expect(rig.log.expiries.isEmpty)
        #expect(await rig.controller.status.phase.isFailed == false)
        await start.release()
        try await rig.waitForPhase(\.isActive)
        #expect(await rig.controller.status.protection == .protected)
        #expect(rig.log.expiries.isEmpty)
        #expect(await rig.controller.needsRecovery == false)
    }

    @Test
    func `a boot start that outlives its own budget expires once is measured blocked and retries behind the first backoff`() async throws {
        let gate = StepGate(point: .createEngine)
        let rig = try await BootRig.make()
        let harness = rig.harness
        await harness.ports.suspend(using: gate)
        let baseline = harness.trace.calls.count
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        await rig.settle()
        try await rig.waitForPendingSleep(.seconds(60))
        #expect(rig.count("engine.create", since: baseline) == 1)

        harness.clock.advance(.seconds(60))
        // The runtime's first backoff is scheduled only after the whole expiry has published and its policy load ended.
        try await rig.waitForPendingSleep(.seconds(5))
        let expired = await rig.controller.status
        #expect(expired.phase == .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false))
        #expect(expired.protection == .blocked)
        #expect(rig.log.expiries == ["operation expired, last step=createEngine"])
        #expect(await harness.ports.policy == .error)
        #expect(await harness.ports.verification() == .blocked)
        #expect(await rig.controller.needsRecovery)
        // A tick-driven retry would wait out the same first step of the schedule.
        #expect(await rig.controller.startup.tickRetryAttempt == 1)
        #expect(await rig.controller.startup.tickRetryAt == harness.clock.now + .seconds(5))

        // The stale engine creation returns into an abandoned generation, which shuts that engine down; the requeue waits
        // out the first backoff. The shutdown is the positive signal that the stale return has been handled.
        await gate.release()
        try await waitForCondition { rig.count("engine.shutdown", since: baseline) >= 1 }
        #expect(rig.count("engine.create", since: baseline) == 1)

        harness.clock.advance(.seconds(5))
        try await rig.waitForPhase(\.isActive)
        let final = await rig.controller.status
        #expect(final.protection == .protected)
        #expect(rig.count("engine.create", since: baseline) == 2)
        #expect(rig.log.expiries.count == 1)
        // From the first blocking measurement on, nothing is claimed unknown and nothing is ever applied open.
        let afterBlocked = rig.recorder.statuses.drop { $0.protection != .blocked }
        #expect(afterBlocked.contains { $0.protection == .unknown } == false)
        #expect(afterBlocked.contains { $0.protection == .unprotected } == false)
        #expect(harness.trace.calls.dropFirst(baseline).contains("pf.disconnected") == false)
        // The abandoned generation's cleanup was deferred to the reconciliation that the requeue ran.
        let generation = await rig.controller.currentGeneration
        #expect(try DaemonJournal(directory: harness.directory).snapshot().resources.map(\.generation) == [generation])
        #expect(await rig.controller.engines.keys.map(\.self) == [generation])
        #expect(await rig.controller.needsRecovery == false)
        // The phase is active before the runtime has heard that reconciliation returned (and has re-checked that the
        // controller no longer needs recovery, M1-30 NF1): wait for the verdict instead of racing it.
        try await waitForCondition { await rig.runtime.isRecovering == false }
        // The first committed reconciliation resets both backoff schedules.
        #expect(await rig.runtime.attempt == 0)
        #expect(await rig.controller.startup.tickRetryAttempt == 0)
        #expect(await rig.controller.startup.tickRetryAt == nil)
    }

    @Test
    func `an expiry inside reconciliation is measured blocked and backs off like an expiry in the start`() async throws {
        let reconciliation = StepGate(point: .validateSecrets)
        let rig = try await BootRig.make(secureInstall: ReconciliationGate(gate: reconciliation))
        let harness = rig.harness
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await reconciliation.release() } }
        await reconciliation.wait()
        await rig.settle()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        #expect(rig.log.expiries == ["operation expired, last step=none"])
        #expect(await rig.controller.status.phase == .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false))
        #expect(await rig.controller.status.protection == .blocked)
        #expect(await harness.ports.policy == .error)
        await reconciliation.release()
        await rig.settle()
        harness.clock.advance(.seconds(5))
        try await rig.waitForPhase(\.isActive)
        #expect(await rig.controller.status.protection == .protected)
        #expect(rig.log.expiries.count == 1)
        #expect(harness.trace.calls.contains("pf.disconnected") == false)
    }

    @Test
    func `an expiry whose blocking policy cannot be measured claims nothing`() async throws {
        let gate = StepGate(point: .createEngine)
        let rig = try await BootRig.make()
        let harness = rig.harness
        await harness.ports.suspend(using: gate)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        await rig.settle()
        try await rig.waitForPendingSleep(.seconds(60))
        await harness.ports.reportVerification(.unknown)
        try await rig.recorder.flush(rig.controller)
        let published = rig.recorder.statuses.count
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        let status = await rig.controller.status
        #expect(status.protection == .unknown)
        #expect(status.phase == .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false))
        #expect(rig.log.expiries == ["operation expired, last step=createEngine"])
        // Every status published after the expiry line, the interim one included, claims only what was measured: nothing
        // here was, so none may say `.blocked` or `blockedByPolicy: true` (mutant: an interim claim without the read).
        try await rig.recorder.flush(rig.controller)
        let afterExpiry = rig.recorder.statuses.dropFirst(published)
        #expect(afterExpiry.isEmpty == false)
        #expect(afterExpiry.contains { $0.protection == .blocked } == false)
        #expect(afterExpiry.contains { $0.phase == .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false) } == false)
    }

    fileprivate enum GapInterference: CaseIterable, Sendable { case none, settings, stop }

    @Test(arguments: GapInterference.allCases)
    func `pf holds blocking with the intent set in the gap between reconciliation and the boot start`(
        _ interference: GapInterference,
    ) async throws {
        let gate = StepGate(point: .applyIntents)
        let rig = try await BootRig.make(steps: gate)
        let harness = rig.harness, controller = rig.controller
        let baseline = harness.trace.calls.count
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        await rig.settle()

        try await assertGapHeld(rig, baseline: baseline)

        var requested = MacGlobalSettings.defaults; requested.lockdown = true
        let settings = requested
        let generationAtGap = await controller.currentGeneration
        let change: Watched<Void>? = switch interference {
        case .none: nil
        case .settings: Watched { try await controller.setGlobalSettings(settings, connectionUID: ControllerHarness.uid) }
        case .stop: Watched { _ = try await controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid) }
        }
        if change != nil {
            // Both controls reserve a generation on entry: that is the proof the request reached the controller.
            try await waitForCondition { await controller.currentGeneration != generationAtGap }
        }
        // A settings change tightens, never opens. An explicit user stop is the legitimate teardown and may finish while
        // the hook is still parked (it cancels the parked stage), so it is checked by its end state below.
        if interference != .stop {
            #expect(await harness.ports.policy != .disconnected)
        }
        await gate.release()
        _ = try await change?.outcome()
        try await assertGapOutcome(interference, rig, baseline: baseline)
    }

    /// The gap: reconciliation committed its work, the start has not begun. pf holds the blocking policy with the intent
    /// set, the start's task already holds the serial slot, and no request or tick can open anything.
    private func assertGapHeld(_ rig: BootRig, baseline: Int) async throws {
        let harness = rig.harness, controller = rig.controller
        #expect(await controller.needsRecovery)
        #expect(await controller.intended != nil)
        #expect(await harness.ports.policy == .error)
        #expect(await harness.ports.verification() == .blocked)
        #expect(await controller.status.protection == .blocked)
        // The start's task already holds the serial slot, and the heartbeat finds it occupied.
        #expect(await controller.startup.bootStart != nil)
        #expect(await controller.operation != nil)
        #expect(try await controller.heartbeatProbe() == false)
        await #expect(throws: DaemonFailure.controllerRecoveryRequired) {
            _ = try await controller.start(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        }
        try await controller.tick()
        #expect(await harness.ports.policy == .error)
        #expect(harness.trace.calls.dropFirst(baseline).contains("pf.disconnected") == false)
    }

    private func assertGapOutcome(_ interference: GapInterference, _ rig: BootRig, baseline: Int) async throws {
        let harness = rig.harness, controller = rig.controller
        switch interference {
        case .none, .settings:
            try await rig.waitForPhase(\.isActive)
            #expect(await controller.status.protection == .protected)
            #expect(harness.trace.calls.dropFirst(baseline).contains("pf.disconnected") == false)
            try await rig.recorder.flush(controller)
            let afterBlocked = rig.recorder.statuses.drop { $0.protection != .blocked }
            #expect(afterBlocked.contains { $0.protection == .unknown || $0.protection == .unprotected } == false)
            if interference == .settings {
                #expect(await controller.settings.lockdown)
            }
        case .stop:
            try await rig.waitForPhase { $0 == .idle }
            #expect(await controller.engines.isEmpty)
            #expect(try DaemonJournal(directory: harness.directory).snapshot().resources.isEmpty)
        }
    }

    @Test(arguments: [3, 5])
    func `repeated expiries back off five fifteen sixty and never faster and the first success resets the schedule`(
        expiries: Int,
    ) async throws {
        let clock = HostClock(), runtime = DaemonRuntime(clock: clock)
        let calls = Mutex(0), revision = Mutex(UUID())
        let ports = DaemonRuntime.Ports(
            startListener: {}, setRecovering: { _ in },
            reconcile: {
                let call = calls.withLock { $0 += 1; return $0 }
                if call <= expiries {
                    // The controller rotates its control identity when the watchdog fires.
                    revision.withLock { $0 = UUID() }
                    throw StartupOperationExpired()
                }
            },
            startMonitors: {}, block: { _ in }, shouldRetry: { true }, shutdown: {},
            revision: { revision.withLock { $0 } },
        )
        let run = Task { await runtime.run(ports: ports) }
        defer { run.cancel() }
        var observed: [Int] = []
        for expected in 1 ... expiries {
            try await waitForCondition { clock.pendingSleeps.count == 1 }
            #expect(calls.withLock { $0 } == expected)
            let delay = try #require(clock.pendingSleeps.first)
            observed.append(Int(delay.components.seconds))
            clock.advance(delay)
        }
        try await waitForCondition { await runtime.isRecovering == false }
        await run.value
        #expect(observed == Array([5, 15, 60, 60, 60].prefix(expiries)))
        #expect(calls.withLock { $0 } == expiries + 1)
        #expect(await runtime.isRecovering == false)
        #expect(await runtime.attempt == 0)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct OperationTimingLogTests {
    @Test
    func `each checkpoint logs its step with the milliseconds since the operation began`() async throws {
        let sink = OperationLogSink(), gate = StepGate(point: .configureInterface)
        let harness = try ControllerHarness(gate: gate, operationLog: sink.append)
        try await harness.install()
        let start = Task { try await harness.start() }
        await gate.wait()
        harness.clock.advance(.milliseconds(2500))
        await gate.release()
        _ = try await start.value
        let lines = sink.lines
        #expect(lines.first == "step validateSecrets begin +0")
        #expect(lines.contains("step createEngine begin +0"))
        #expect(lines.contains("step configureInterface begin +2500"))
        #expect(lines.contains("step installRoutes begin +2500"))
        // Fixed vocabulary only: step names and integers, nothing derived from an error, a profile or a secret.
        let shape = #/^(step [A-Za-z]+ begin \+[0-9]+|operation expired, last step=[A-Za-z]+)$/#
        #expect(lines.allSatisfy { $0.wholeMatch(of: shape) != nil })
    }
}

/// The expiry's own suspension point (its first verification read): what it publishes afterwards is fenced.
@Suite(.timeLimit(.minutes(1)))
private struct ExpiryFenceTests {
    @Test
    func `a stop that completes while the expiry is parked in its first read is not overwritten`() async throws {
        let read = PolicyReadGate(.verification, armed: false)
        let create = StepGate(point: .createEngine)
        let harness = try ControllerHarness(portsTransform: { $0.gatingPolicy(read) })
        try await harness.install()
        await harness.ports.suspend(using: create)
        let recorder = StatusRecorder(harness.controller.wireEvents.observe())
        let start = Watched { try await harness.start() }
        defer { start.cancel(); read.release(); Task { await create.release() } }
        await create.wait()
        try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(60)) }
        read.arm()
        harness.clock.advance(.seconds(60))
        // The expiry has fenced the operation and is now inside its first verification read.
        await read.wait()
        let stopped = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.controller.status.phase == .idle)
        #expect(await harness.controller.status.protection == .unprotected)
        // The expiry resumes into a newer generation: it must publish nothing. The start's own failure ends once the read
        // returns (boundedResult resumes after operationExpired), which is the join.
        read.release()
        _ = try await start.outcome()
        try await recorder.flush(harness.controller)
        #expect(await harness.controller.currentGeneration == stopped)
        let status = await harness.controller.status
        #expect(status.phase == .idle)
        #expect(status.protection == .unprotected)
        let tail = recorder.statuses.drop { $0.phase != .idle }
        #expect(tail.isEmpty == false)
        #expect(tail.allSatisfy { $0.phase == .idle && $0.protection == .unprotected }, "the expiry published over the finished stop")
    }
}
