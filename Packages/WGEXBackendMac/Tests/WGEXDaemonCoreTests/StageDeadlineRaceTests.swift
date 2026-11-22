// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-29 R1: the hand-over to the boot-intent start happens inside stage 1's own actor turn and moves the serial slot. A
/// stage-1 deadline that had already won the continuation, and reaches the actor just after that turn, finds a slot that is
/// no longer its own. It must not report a stage-1 failure (which drained the running boot start and, on expiry, skipped
/// the first 5 s backoff step), and stage 2's own deadline and backoff must then apply unchanged.
@Suite(.timeLimit(.minutes(1)))
private struct StageDeadlineRaceTests {
    @Test
    func `a stage 1 deadline firing inside the hand-over turn is no failure and the backoff schedule is kept`() async throws {
        let install = ParkingSecureInstall()
        let create = StepGate(point: .createEngine)
        let watchdog = HookedClock()
        let rig = try await BootRig.make(secureInstall: install, watchdogClock: watchdog)
        let harness = rig.harness, controller = rig.controller
        await harness.ports.suspend(using: create)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await create.release() } }
        await install.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(59))

        // Inside the actor turn that hands the boot start over (the slot assignment reads the watchdog clock, and the
        // reservation is already made), the last second of stage 1's budget passes. The deadline task wakes and wins the
        // continuation while the stage's task is still mid-turn; its hop to the actor therefore lands after the hand-over.
        // The pause keeps the actor turn open until that deadline task has certainly run.
        watchdog.arm {
            guard controller.assumeIsolated({ $0.startup.bootStart != nil }) else { return false }
            harness.clock.advance(.seconds(1))
            usleep(150_000)
            return true
        }
        install.release()
        try await waitForCondition { watchdog.fired }
        let parked = Watched { await create.wait() }
        _ = try await parked.outcome()

        // The boot start is running as its own operation: no failure, no drain, no backoff step spent.
        #expect(rig.log.expiries.isEmpty, "stage 1's late deadline was reported as an expiry")
        #expect(await controller.startup.bootStart != nil, "the running boot start was torn down by a stage-1 failure")
        #expect(await controller.startup.tickRetryAttempt == 0)
        #expect(await controller.startup.tickRetryAt == nil)
        #expect(await controller.status.phase.isFailed == false)
        #expect(rig.log.lines.filter { $0 == "startup stage deadline fired after its hand-over; not an expiry" }.count == 1)

        // Stage 2's own deadline is the only expiry, and the retry waits the full first backoff step.
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        #expect(rig.log.expiries.count == 1)
        #expect(harness.clock.pendingSleeps == [.seconds(5)], "the backoff step was skipped or doubled")
        #expect(await controller.status.phase.isActive == false)
        let creates = rig.count("engine.create")

        // The abandoned create returns; its latch clears; the retry then starts the tunnel after its 5 s.
        await create.release()
        try await waitForCondition { await controller.outstandingOffActor.isEmpty }
        #expect(rig.count("engine.create") == creates)
        harness.clock.advance(.seconds(5))
        try await rig.waitForPhase(\.isActive)
        #expect(await controller.status.protection == .protected)
        #expect(rig.log.expiries.count == 1)
    }
}

/// M1-29 R5, mutant M19: an expiry clears the reserved boot start together with the serial slot, before its first
/// suspension. The stage's own failure path would clear it later, once the expiry has finished and resumed the waiter, so
/// only the expiry's measurement window shows it: there the controller has no operation, and must have no pending start.
@Suite(.timeLimit(.minutes(1)))
private struct ExpiredBootStartTests {
    @Test
    func `an expired boot start leaves no pending reservation beside an empty serial slot while the expiry measures`() async throws {
        let create = StepGate(point: .createEngine)
        let read = PolicyReadGate(.verification, armed: false)
        let rig = try await BootRig.make(portsTransform: { $0.gatingPolicy(read) })
        let harness = rig.harness, controller = rig.controller
        await harness.ports.suspend(using: create)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await create.release(); read.release() } }
        let parked = Watched { await create.wait() }
        _ = try await parked.outcome()
        try await rig.waitForPendingSleep(.seconds(60))
        #expect(await controller.startup.bootStart != nil)
        read.arm()
        harness.clock.advance(.seconds(60))
        let measuring = Watched { await read.wait() }
        _ = try await measuring.outcome()

        // The expiry is parked in its first measurement of the policy: the slot is empty, so no start may be pending.
        #expect(rig.log.expiries.count == 1)
        #expect(await controller.operation == nil)
        #expect(await controller.startup.bootStart == nil, "the expired stage's reservation outlived its slot")
        #expect(await controller.bootStartSlotIsEmpty == false)

        read.release()
        try await rig.waitForPendingSleep(.seconds(5))
        #expect(await controller.startup.bootStart == nil)
    }
}
