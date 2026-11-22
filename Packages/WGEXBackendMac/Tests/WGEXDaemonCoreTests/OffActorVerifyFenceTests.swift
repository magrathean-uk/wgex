// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-29 R5, mutant M12: `verifyOffActor` re-checks the generation when the protection verifier returns. The start path's
/// caller re-checks next, so only a site where `verifyPolicy` follows the verifier shows what the re-check is for: the
/// captive close re-measures the policy (a pf canary evaluation, which can also publish `unknown`) as soon as the
/// verifier returns, so a stale close must stop at the verifier.
@Suite(.timeLimit(.minutes(1)))
private struct OffActorVerifyFenceTests {
    /// The pf canary evaluations made from the moment the stop is admitted until it is done. With `parkClose` the stop
    /// arrives while a captive close is parked inside the verifier, and the close's verifier returns after it.
    private func canaryChecksAroundStop(parkClose: Bool) async throws -> Int {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let controller = harness.controller
        try await controller.openCaptiveWindow(seconds: 300, connectionUID: ControllerHarness.uid)
        let gate = StepGate(point: .verify)
        let profile = harness.profile.id
        guard parkClose else {
            let before = await harness.ports.canaryChecks
            _ = try await controller.stop(profileID: profile, connectionUID: ControllerHarness.uid)
            return await harness.ports.canaryChecks - before
        }
        await harness.ports.suspendVerify(using: gate)
        let close = Watched { try await controller.closeCaptiveWindow() }
        defer { close.cancel(); Task { await gate.release() } }
        let parked = Watched { await gate.wait() }
        _ = try await parked.outcome()
        let generation = await controller.currentGeneration

        // A stop arrives while the verifier is parked: it takes a new generation and waits for the close to end.
        let stop = Watched { _ = try await controller.stop(profileID: profile, connectionUID: ControllerHarness.uid) }
        try await waitForCondition { await controller.currentGeneration != generation }
        let before = await harness.ports.canaryChecks
        await gate.release()
        _ = try await stop.outcome()
        _ = try await close.outcome()
        #expect(await controller.status.phase == .idle)
        #expect(await controller.status.protection == .unprotected)
        return await harness.ports.canaryChecks - before
    }

    @Test
    func `a captive close whose verifier returns after a stop does not measure the policy again`() async throws {
        let alone = try await canaryChecksAroundStop(parkClose: false)
        let withStaleClose = try await canaryChecksAroundStop(parkClose: true)
        #expect(
            withStaleClose == alone,
            "the stale close measured the policy \(withStaleClose - alone) time(s) after the verifier returned",
        )
    }
}
