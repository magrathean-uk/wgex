// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

/// M1-30 NF1: a boot-intent start (stage 2) that ends before the stage-1 waiter resumes is still observed. Before, stage 2's
/// own cleanup cleared the pending start the waiter looked up, so `reconcileAtStartup` returned success with the finished
/// start's task still in the serial slot and `needsRecovery` still true: the runtime then called `recovered()` and nothing
/// retried until an unrelated event drained the slot, with pf blocking and no recovery scheduled.
@Suite(.timeLimit(.minutes(2)))
private struct BootStage2LivenessTests {
    /// What a settled boot looks like to the runtime and the controller.
    private struct Outcome {
        var stuck = false
        var isRecovering = true
        var needsRecovery = true
        var slotOccupied = false
        var bootStartPending = false
        var attempt = 0
        var fiveSecondRetryPending = false
        var failed = false
        var policy: PacketFilterPolicy = .disconnected
        var verification: PFVerificationStatus = .unknown
        var claimedProtected = false
        var guardLines = 0
    }

    private enum Stage2 { case injectedThrow, secureInstallRegresses }

    /// Boots a daemon whose stage 2 ends within the stage-1 waiter's resumption latency, once. With `hooked`, stage 1's own
    /// deadline is also placed inside the hand-over turn (VERIFY M1-29 appendix). Settles without moving manual time past
    /// the release, and returns what it finds, or `nil` to say the run was a retry-success control.
    private func boot(_ kind: Stage2, hooked: Bool) async throws -> (BootRig, ParkingSecureInstall, Outcome) {
        let install = ParkingSecureInstall(), watchdog = HookedClock()
        let steps = StepGate(point: .applyIntents, failing: true, enabled: kind == .injectedThrow)
        let rig = try await BootRig.make(steps: steps, secureInstall: install, watchdogClock: watchdog)
        let harness = rig.harness, controller = rig.controller
        if kind == .secureInstallRegresses {
            install.answerLater(.needsAttention(.inspectionFailed))
        }
        let run = rig.run()
        _ = run
        await install.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        if hooked {
            harness.clock.advance(.seconds(59))
            watchdog.arm {
                guard controller.assumeIsolated({ $0.startup.bootStart != nil }) else { return false }
                harness.clock.advance(.seconds(1))
                usleep(150_000)
                return true
            }
        }
        install.release()
        // The runtime either backs off (a retry sleeping 5 s) or has declared recovery over: both end the wait at once.
        let runtime = rig.runtime
        let settled = await eventually(within: .seconds(10)) {
            await !runtime.isRecovering || harness.clock.pendingSleeps.contains(.seconds(5))
        }
        #expect(settled, "neither a retry nor a recovery verdict followed the release")
        let isRecovering = await runtime.isRecovering
        var outcome = Outcome()
        outcome.isRecovering = isRecovering
        outcome.needsRecovery = await controller.needsRecovery
        outcome.slotOccupied = await controller.operation != nil
        outcome.bootStartPending = await controller.startup.bootStart != nil
        outcome.attempt = await runtime.attempt
        outcome.fiveSecondRetryPending = harness.clock.pendingSleeps.contains(.seconds(5))
        outcome.failed = await controller.status.phase.isFailed
        outcome.policy = await harness.ports.policy
        outcome.verification = await harness.ports.verification()
        try await rig.recorder.flush(controller)
        outcome.claimedProtected = rig.recorder.statuses.contains { $0.protection == .protected || $0.phase.isActive }
        outcome.guardLines = rig.log.recoveryGuardLines.count
        outcome.stuck = !isRecovering && outcome.needsRecovery
        return (rig, install, outcome)
    }

    private func expectBackedOff(_ outcome: Outcome, _ context: String) {
        #expect(!outcome.stuck, "\(context): the runtime declared recovery over while needsRecovery was still true")
        #expect(outcome.isRecovering == outcome.needsRecovery, "\(context): isRecovering disagrees with needsRecovery")
        #expect(outcome.needsRecovery, "\(context)")
        #expect(outcome.fiveSecondRetryPending, "\(context): no 5 s retry is pending")
        #expect(!outcome.slotOccupied, "\(context): the finished start's task still holds the serial slot")
        #expect(!outcome.bootStartPending, "\(context): a boot start is still pending")
        #expect(outcome.failed, "\(context): no failure was published")
        #expect(outcome.policy == .error, "\(context): pf is not blocking")
        #expect(outcome.verification == .blocked, "\(context): the blocking is not measured")
        #expect(!outcome.claimedProtected, "\(context): a status claimed protection")
        // The controller's own failure path backed off, so the runtime's guard (a second line of defence) did not fire.
        #expect(outcome.guardLines == 0, "\(context): the runtime guard fired")
    }

    /// Both arms of VERIFY's fastStage2 schedule, repeated: the race is a few scheduler hops wide, so one run proves little,
    /// and every settled run must be backed off.
    @Test(arguments: [false, true])
    func `a start that throws before the stage 1 waiter resumes takes the failure path and the backoff`(hooked: Bool) async throws {
        var stuck = 0
        for round in 0 ..< (hooked ? 8 : 20) {
            let (rig, _, outcome) = try await boot(.injectedThrow, hooked: hooked)
            defer { Task { await rig.runtime.stop() } }
            expectBackedOff(outcome, "round \(round), hooked \(hooked)")
            guard !outcome.stuck else { stuck += 1; continue }
            #expect(await rig.controller.status.recoveryFailureReason == .intentStartFailed, "round \(round)")
            #expect(outcome.attempt == 1, "round \(round): the retry did not use the first backoff step")
            #expect(await rig.controller.startup.tickRetryAttempt == 1)
            // The retry then succeeds: the injected failure was one-shot.
            rig.harness.clock.advance(.seconds(5))
            try await rig.waitForPhase(\.isActive)
            #expect(await rig.controller.status.protection == .protected)
            #expect(await rig.controller.needsRecovery == false)
            try await waitForCondition { await !rig.runtime.isRecovering }
        }
        #expect(stuck == 0, "\(stuck) runs left the daemon stuck")
    }

    /// The realistic case: performStart's secure-install read (its first await) answers not verified one hop into stage 2,
    /// after stage 1 read verified. It throws outside failStart, so only the stage-1 waiter can observe it.
    @Test(arguments: [false, true])
    func `a start whose secure install reads not verified retries on the backoff and recovers when it verifies`(hooked: Bool) async throws {
        var stuck = 0
        for round in 0 ..< (hooked ? 8 : 20) {
            let (rig, install, outcome) = try await boot(.secureInstallRegresses, hooked: hooked)
            defer { Task { await rig.runtime.stop() } }
            expectBackedOff(outcome, "round \(round), hooked \(hooked)")
            guard !outcome.stuck else { stuck += 1; continue }
            // The mid-boot secure-install failure keeps its own label from the first failure on (M1-31): the app shows
            // "secure install is not complete", not the generic start-failure copy, and no status says otherwise.
            #expect(
                await rig.controller.status.recoveryFailureReason == .secureInstallRequired,
                "round \(round): the failure was published as the wrong reason",
            )
            try await rig.recorder.flush(rig.controller)
            #expect(
                rig.recorder.statuses.allSatisfy { $0.recoveryFailureReason != .intentStartFailed },
                "round \(round): a status carried the generic start-failure reason",
            )
            #expect(
                await rig.controller.startup.tickRetryAttempt == 1,
                "round \(round): the controller's own retry schedule did not advance",
            )
            // Until the install verifies again, nothing recovers: the next read still fails.
            install.answerLater(.verified)
            rig.harness.clock.advance(.seconds(5))
            try await rig.waitForPhase(\.isActive)
            #expect(await rig.controller.status.protection == .protected)
            #expect(await rig.controller.needsRecovery == false)
            try await waitForCondition { await !rig.runtime.isRecovering }
            #expect(await rig.controller.operation == nil)
        }
        #expect(stuck == 0, "\(stuck) runs left the daemon stuck")
    }

    /// VERIFY M1-31 N1 (VF131Stale): the mid-boot regression sets the pending secure policy while stage 2 holds the serial slot,
    /// where nothing can clear it. When the install verifies again at the retry, the flag is stale: the next tick must not
    /// apply the failure policy to the healthy tunnel nor republish it as "secure install is not complete".
    @Test
    func `a healed mid-boot secure-install regression leaves no stale failure policy for the following ticks`() async throws {
        for round in 0 ..< 5 {
            let (rig, install, outcome) = try await boot(.secureInstallRegresses, hooked: false)
            defer { Task { await rig.runtime.stop() } }
            expectBackedOff(outcome, "round \(round)")
            install.answerLater(.verified)
            rig.harness.clock.advance(.seconds(5))
            try await rig.waitForPhase(\.isActive)
            try await waitForCondition { await !rig.runtime.isRecovering }
            #expect(await rig.controller.needsRecovery == false, "round \(round)")
            // The tunnel is healthy: its peer handshakes, so no tick has a reason to rotate endpoints or reassert.
            let peer = try #require(rig.harness.profile.peers.first?.publicKey)
            await rig.controller.consume(
                .handshakeCompleted(peer: peer, at: rig.harness.clock.wallNow), generation: rig.controller.currentGeneration,
            )
            try await rig.recorder.flush(rig.controller)
            let healed = rig.recorder.statuses.count
            for (index, step) in [Duration.zero, .seconds(5), .seconds(5)].enumerated() {
                rig.harness.clock.advance(step)
                try? await rig.controller.tick()
                let context = "round \(round), tick \(index)"
                let policy = await rig.harness.ports.policy
                if case .connected = policy {} else {
                    Issue.record("\(context): pf is \(policy), not connected")
                }
                #expect(await rig.controller.status.phase.isActive, "\(context): the phase left active")
                #expect(await rig.controller.status.protection == .protected, "\(context): protection is not protected")
                #expect(await rig.controller.status.recoveryFailureReason == nil, "\(context): a failure reason is still published")
                #expect(await rig.controller.maintenanceState.securePolicyPending == false, "\(context): a stale secure policy is pending")
            }
            try await rig.recorder.flush(rig.controller)
            let after = Array(rig.recorder.statuses.dropFirst(healed))
            #expect(
                after.allSatisfy { $0.recoveryFailureReason != .secureInstallRequired && $0.protection != .unknown },
                "round \(round): a status after the heal said the install is not complete or protection unknown",
            )
        }
    }

    /// Control for the fix above: an install that never verifies keeps the failure policy, measured, and the backoff.
    @Test
    func `an install that stays unverified keeps blocking, measured, and backs off 5 then 15 seconds`() async throws {
        for round in 0 ..< 5 {
            let (rig, install, outcome) = try await boot(.secureInstallRegresses, hooked: false)
            defer { Task { await rig.runtime.stop() } }
            expectBackedOff(outcome, "round \(round)")
            install.answerLater(.needsAttention(.inspectionFailed))
            rig.harness.clock.advance(.seconds(5))
            try await rig.waitForPendingSleep(.seconds(15))
            for (index, step) in [Duration.zero, .seconds(5)].enumerated() {
                rig.harness.clock.advance(step)
                try? await rig.controller.tick()
                let context = "round \(round), tick \(index)"
                #expect(await rig.harness.ports.policy == .error, "\(context): pf is not blocking")
                #expect(await rig.harness.ports.verification() == .blocked, "\(context): the blocking is not measured")
                #expect(await rig.controller.status.recoveryFailureReason == .secureInstallRequired, "\(context)")
                #expect(await rig.controller.status.protection == .unknown, "\(context)")
                #expect(await rig.controller.status.phase.isFailed, "\(context)")
                #expect(await rig.controller.needsRecovery, "\(context)")
            }
            #expect(await rig.runtime.attempt >= 2, "round \(round): the backoff did not advance")
        }
    }

    /// The runtime's own guard: a reconcile that returns while the controller still says it needs recovery is not recovery.
    /// Each refusal says so once, in fixed words, so a guest run can grep for it (M1-31).
    @Test
    func `the runtime does not declare recovery while the controller still needs it`() async throws {
        let clock = HostClock(), runtime = DaemonRuntime(clock: clock)
        let incomplete = Mutex(true), recovering = Mutex<[Bool]>([]), lines = Mutex<[String]>([])
        let ports = DaemonRuntime.Ports(
            startListener: {},
            setRecovering: { value in recovering.withLock { $0.append(value) } },
            reconcile: {},
            startMonitors: {},
            block: { _ in },
            shouldRetry: { true },
            shutdown: {},
            recoveryIncomplete: { incomplete.withLock { $0 } },
            log: { line in lines.withLock { $0.append(line) } },
        )
        let run = Task { await runtime.run(ports: ports) }
        defer { run.cancel(); Task { await runtime.stop() } }
        try await waitForCondition { clock.pendingSleeps.contains(.seconds(5)) }
        #expect(await runtime.isRecovering, "recovered() ran while the controller still needed recovery")
        #expect(recovering.withLock { $0 } == [true])
        // First refusal: one line, in the existing operation-log style, with no value of any kind in it.
        #expect(lines.withLock { $0 } == [Self.guardLine])
        // Second refusal (the 5 s retry reconciles again, still incomplete): one more line, not a burst.
        clock.advance(.seconds(5))
        try await waitForCondition { clock.pendingSleeps.contains(.seconds(15)) }
        #expect(lines.withLock { $0 } == [Self.guardLine, Self.guardLine])
        incomplete.withLock { $0 = false }
        clock.advance(.seconds(15))
        try await waitForCondition { await !runtime.isRecovering }
        #expect(recovering.withLock { $0 } == [true, false])
        // Recovery completing says nothing more: the line appears exactly when the guard fires.
        #expect(lines.withLock { $0 } == [Self.guardLine, Self.guardLine])
    }

    /// A reconcile that leaves nothing to recover never touches the guard or its line.
    @Test
    func `a completed recovery logs no guard line`() async {
        let clock = HostClock(), runtime = DaemonRuntime(clock: clock)
        let lines = Mutex<[String]>([]), recovering = Mutex<[Bool]>([])
        let ports = DaemonRuntime.Ports(
            startListener: {},
            setRecovering: { value in recovering.withLock { $0.append(value) } },
            reconcile: {},
            startMonitors: {},
            block: { _ in },
            shouldRetry: { true },
            shutdown: {},
            recoveryIncomplete: { false },
            log: { line in lines.withLock { $0.append(line) } },
        )
        await runtime.run(ports: ports)
        defer { Task { await runtime.stop() } }
        #expect(recovering.withLock { $0 } == [true, false])
        #expect(lines.withLock { $0 }.isEmpty)
    }

    private static let guardLine = "recovery guard: reconcile returned with recovery still needed; recovered() refused, backing off"
}
