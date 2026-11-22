// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

/// A secure-install adapter whose answer a test flips between reads: the install regresses and heals on the schedule the
/// test writes, not on the first or the nth read.
private final class SwitchableSecureInstall: SecureInstallChecking {
    private let state = Mutex<SecureInstallReport.State>(.verified)
    func set(_ next: SecureInstallReport.State) {
        state.withLock { $0 = next }
    }

    func status() async -> SecureInstallReport {
        var report = VerifiedSecureInstall().status()
        report.state = state.withLock { $0 }
        return report
    }

    func perform() async -> SecureInstallReport {
        await status()
    }
}

/// M1-33 VERIFY F2: a regression that is read while another operation holds the serial slot raises a pending secure policy,
/// and the request lives exactly as long as the regression it was raised for (ADR-009). The fail-closed half (a regression
/// still present applies the failure policy once the slot frees, measured) and the healing half (a regression that healed
/// before the slot frees leaves a healthy tunnel connected) are each pinned here on the manual clock, by a periodic pf
/// verification held inside a tick (`PolicyReadGate`), so neither depends on the stage-2 control that `ResilienceSafetyTests`
/// and `BootStage2LivenessTests` use.
@Suite(.timeLimit(.minutes(1)))
private struct PendingSecurePolicyTests {
    /// An active tunnel (booted through the production recovery wiring) and a tick held inside its periodic pf verification,
    /// so the serial slot is busy. `peer` handshakes, so no later tick has a reason to rotate endpoints or reassert.
    private struct HeldTick {
        let rig: BootRig
        let install: SwitchableSecureInstall
        let read: PolicyReadGate
        let run: Task<Void, Never>
        let tick: Watched<Void>
    }

    private func holdATick() async throws -> HeldTick {
        let install = SwitchableSecureInstall(), read = PolicyReadGate(.verification, armed: false)
        let rig = try await BootRig.make(secureInstall: install, portsTransform: { $0.gatingPolicy(read) })
        let controller = rig.controller
        let run = rig.run()
        try await rig.waitForPhase(\.isActive)
        try await waitForCondition { await !rig.runtime.isRecovering }
        #expect(await controller.needsRecovery == false)
        let peer = try #require(rig.harness.profile.peers.first?.publicKey)
        await controller.consume(
            .handshakeCompleted(peer: peer, at: rig.harness.clock.wallNow), generation: controller.currentGeneration,
        )
        read.arm()
        rig.harness.clock.advance(.seconds(5))
        let tick = Watched { try await controller.tick() }
        await read.wait()
        #expect(await controller.operation != nil, "the held tick does not occupy the serial slot")
        return HeldTick(rig: rig, install: install, read: read, run: run, tick: tick)
    }

    private func finish(_ held: HeldTick) async {
        held.read.release()
        held.run.cancel()
        await held.rig.runtime.stop()
    }

    private func expectConnected(_ rig: BootRig, _ context: String) async {
        let policy = await rig.harness.ports.policy
        if case .connected = policy {} else {
            Issue.record("\(context): pf is \(policy), not connected")
        }
    }

    /// The regression is still present when the slot frees: the pending request applies the failure policy, measured, and
    /// the next ticks keep it.
    @Test
    func `a regression read while the slot is held applies the failure policy when the slot frees and keeps it`() async throws {
        let held = try await holdATick()
        let rig = held.rig, controller = rig.controller
        defer { Task { await finish(held) } }

        held.install.set(.needsAttention(.inspectionFailed))
        await #expect(throws: DaemonError.secureInstallRequired) { try await controller.tick() }
        // Read with the slot busy: the request is raised and kept, and pf stays on the tunnel-only policy meanwhile.
        #expect(await controller.maintenanceState.securePolicyPending, "the regression raised no pending request")
        #expect(await controller.startup.secureInstallRegressed)
        await expectConnected(rig, "while the slot is held")
        #expect(held.tick.isFinished == false)

        held.read.release()
        _ = try await held.tick.outcome()
        #expect(await rig.harness.ports.policy == .error, "the slot freed and pf is not blocking")
        #expect(await rig.harness.ports.verification() == .blocked, "the blocking is not measured")
        #expect(await controller.status.protection == .unknown)
        #expect(await controller.status.recoveryFailureReason == .secureInstallRequired)
        #expect(await controller.maintenanceState.securePolicyPending == false, "the request was not consumed")

        for (index, step) in [Duration.zero, .seconds(5)].enumerated() {
            rig.harness.clock.advance(step)
            await #expect(throws: DaemonError.secureInstallRequired) { try await controller.tick() }
            let context = "tick +\(index == 0 ? 0 : 5) s"
            #expect(await rig.harness.ports.policy == .error, "\(context): pf is not blocking")
            #expect(await rig.harness.ports.verification() == .blocked, "\(context): the blocking is not measured")
            #expect(await controller.status.protection == .unknown, "\(context)")
            #expect(await controller.status.recoveryFailureReason == .secureInstallRequired, "\(context)")
        }
    }

    /// The regression is read with the slot held and heals, by another read, before the slot frees: the request it raised is
    /// stale, so the healthy tunnel stays connected and measured protected (M1-33 N1 on the maintenance path).
    @Test
    func `a regression that heals before the slot frees leaves the tunnel connected`() async throws {
        let held = try await holdATick()
        let rig = held.rig, controller = rig.controller
        defer { Task { await finish(held) } }

        held.install.set(.needsAttention(.inspectionFailed))
        await #expect(throws: DaemonError.secureInstallRequired) { try await controller.tick() }
        #expect(await controller.maintenanceState.securePolicyPending, "the regression raised no pending request")
        held.install.set(.verified)
        try await controller.tick()
        #expect(await controller.startup.secureInstallRegressed == false, "the heal read did not clear the regression")
        await expectConnected(rig, "after the heal, slot held")

        held.read.release()
        _ = try await held.tick.outcome()
        #expect(await controller.maintenanceState.securePolicyPending == false, "a stale request outlived the heal")
        await expectConnected(rig, "slot freed")
        #expect(await rig.harness.ports.verification() != .blocked, "the healthy tunnel was blocked")

        for (index, step) in [Duration.zero, .seconds(5), .seconds(5)].enumerated() {
            rig.harness.clock.advance(step)
            try? await controller.tick()
            let context = "tick \(index)"
            await expectConnected(rig, context)
            #expect(await controller.status.phase.isActive, "\(context): the phase left active")
            #expect(await controller.maintenanceState.securePolicyPending == false, "\(context): a stale request is pending")
            if index > 0 {
                #expect(await controller.status.protection == .protected, "\(context): protection is not protected")
                #expect(await controller.status.recoveryFailureReason == nil, "\(context): a failure reason is still published")
            }
        }
    }
}
