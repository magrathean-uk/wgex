// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25 fix pass 1, B1: the boot hand-over from reconciliation to the boot-intent start never leaves the serial slot
/// empty (or holding a completed task) while the start is pending. A concurrent drain (the login and power monitors) or the
/// recovery heartbeat would otherwise find the slot free and start a second operation beside the boot start.
@Suite(.timeLimit(.minutes(2)))
private struct BootHandOverTests {
    fileprivate enum Entry: String, CaseIterable, Sendable { case drainLifecycle, consoleUserChanged }

    private final class Violations: Sendable {
        private let count = Mutex(0)
        private let probes = Mutex(0)
        func record(_ violated: Bool) {
            probes.withLock { $0 += 1 }
            if violated {
                count.withLock { $0 += 1 }
            }
        }

        var violations: Int {
            count.withLock { $0 }
        }

        var samples: Int {
            probes.withLock { $0 }
        }
    }

    /// One boot: reconciliation parked at its first suspension, drains arriving through `entry` while it is parked, and
    /// heartbeat spinners (the production heartbeat fires every 5 s; spinners stand in for the interleavings it would meet).
    /// The completion of the drains and the reconciliation's own waiter are two continuations on one task, so which runs
    /// first is not fixed: the schedule is repeated.
    private func boot(entry: Entry) async throws -> Violations {
        let install = ParkingSecureInstall()
        let rig = try await BootRig.make(secureInstall: install)
        let controller = rig.controller
        let seen = Violations()
        let stop = Mutex(false)
        let run = rig.run()
        await install.wait()
        let drains = (0 ..< 6).map { _ in
            Watched {
                switch entry {
                case .drainLifecycle: await controller.drainLifecycle()
                case .consoleUserChanged: try await controller.consoleUserChanged(nil)
                }
            }
        }
        let spinners = (0 ..< 4).map { _ in
            Task {
                while !stop.withLock({ $0 }) {
                    let violated = await (try? controller.heartbeatProbe()) ?? false
                    seen.record(violated)
                    await Task.yield()
                }
            }
        }
        install.release()
        try await rig.waitForPhase(\.isActive)
        try await waitForCondition { await controller.needsRecovery == false }
        for drain in drains {
            _ = try await drain.outcome()
        }
        stop.withLock { $0 = true }
        for spinner in spinners {
            await spinner.value
        }
        await rig.runtime.stop()
        run.cancel()
        // The boot start ended through its own stage, once, and nothing else ran beside it.
        #expect(await controller.startup.bootStart == nil)
        #expect(await controller.status.protection == .protected)
        #expect(rig.log.expiries.isEmpty)
        return seen
    }

    @Test(arguments: Entry.allCases)
    func `a drain or heartbeat during reconciliation never finds the slot empty while the boot start is pending`(
        _ entry: Entry,
    ) async throws {
        var violations = 0, samples = 0
        for _ in 0 ..< 30 {
            let seen = try await boot(entry: entry)
            violations += seen.violations; samples += seen.samples
        }
        #expect(samples > 0)
        #expect(violations == 0, "the serial slot was empty while a boot start was pending, \(violations) of \(samples) heartbeat probes")
    }

    @Test
    func `the recovery heartbeat through the production runtime port never enters while the boot start runs`() async throws {
        let create = StepGate(point: .createEngine)
        let rig = try await BootRig.make(heartbeat: true)
        let harness = rig.harness
        await harness.ports.suspend(using: create)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await create.release() } }
        await create.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        let slot = await rig.controller.operationID
        let reads = await harness.ports.verificationReads
        // Eleven heartbeat periods inside the start's 60 s: every tick meets an occupied slot.
        for _ in 0 ..< 11 {
            harness.clock.advance(.seconds(5))
            try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(5)) }
            #expect(await rig.controller.operationID == slot)
            #expect(await harness.ports.verificationReads == reads, "a heartbeat measured the policy during the boot start")
        }
        #expect(rig.log.expiries.isEmpty)
        await create.release()
        try await rig.waitForPhase(\.isActive)
        #expect(await rig.controller.status.protection == .protected)
    }
}
