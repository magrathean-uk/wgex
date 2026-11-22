// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25 fix pass 1, B4: an off-actor adapter call that the watchdog abandoned and that never returns must not be issued
/// again on every retry. The cooperative pool is as wide as the core count; one parked thread per expiry cycle would
/// exhaust it, and with it the controller actor, the watchdog and every XPC reply.
@Suite(.timeLimit(.minutes(2)))
private struct OffActorLatchTests {
    @Test
    func `a never-returning engine creation parks one pool thread across the whole retry schedule`() async throws {
        let block = ThreadBlock()
        let rig = try await BootRig.make(portsTransform: { ports in
            ports.replacingEngineFactory(BlockingEngineFactory(base: ports.engineFactory, block: block))
        })
        let harness = rig.harness, controller = rig.controller
        let baseline = harness.trace.calls.count
        let run = rig.run()
        defer {
            run.cancel()
            Task { await rig.runtime.stop() }
            for _ in 0 ..< block.entries + 4 {
                block.open()
            }
        }
        try await waitForCondition { block.entered }
        try await rig.waitForPendingSleep(.seconds(60))
        #expect(block.entries == 1)

        // The first attempt expires; each of the four retries behind the 5, 15, 60, 60 s schedule then finds the call still
        // outstanding and fails at once. The runtime's attempt counter, not the pending sleeps alone, marks each cycle: a
        // running stage also holds a 60 s deadline sleep.
        harness.clock.advance(.seconds(60))
        let schedule = [5, 15, 60, 60, 60]
        for (index, delay) in schedule.enumerated() {
            // A second parked thread ends the schedule at once: that is the failure, and a retry that parked it would
            // otherwise sit out its own 60 s deadline here.
            try await waitForCondition {
                if block.entries > 1 {
                    return true
                }
                let attempt = await rig.runtime.attempt
                return attempt == index + 1 && harness.clock.pendingSleeps == [.seconds(delay)]
            }
            // Each refused retry says so once, in fixed words, so a guest run can tell a refusal from a real failure.
            let refusals = rig.log.lines.filter { $0.hasPrefix("off-actor") }
            #expect(refusals.count == index, "one line per refusal: \(refusals.count) lines after \(index) refused attempts")
            #expect(refusals.allSatisfy { $0 == "off-actor createEngine still outstanding; attempt refused" })
            guard block.entries == 1, index < schedule.count - 1 else { break }
            harness.clock.advance(.seconds(delay))
        }
        #expect(block.entries == 1, "an abandoned create was issued again: \(block.entries) pool threads parked")
        #expect(rig.count("engine.create", since: baseline) == 0)

        // Fail-closed throughout: pf holds the blocking policy, measured, and no status ever claims otherwise.
        #expect(await harness.ports.policy == .error)
        #expect(await harness.ports.verification() == .blocked)
        #expect(harness.trace.calls.dropFirst(baseline).contains("pf.disconnected") == false)
        let status = await controller.status
        #expect(status.protection == .blocked)
        try await rig.recorder.flush(controller)
        let afterBlocked = rig.recorder.statuses.drop { $0.protection != .blocked }
        #expect(afterBlocked.contains { $0.protection == .unprotected } == false)
        #expect(await controller.needsRecovery)
    }
}
