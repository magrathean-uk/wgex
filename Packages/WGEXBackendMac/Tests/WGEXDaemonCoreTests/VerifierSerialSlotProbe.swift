// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore

// Verifier regression: a cancelled awaiter must not release the serial slot while its operation runs.
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct VerifierSerialSlotProbe {
    private func settle() async {
        for _ in 0 ..< 2000 {
            await Task.yield()
        }
    }

    @Test
    func `A cancelled networkChanged caller keeps the slot`() async throws {
        let gate = StepGate(point: .installRoutes)
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.ports.suspend(using: gate)
        let caller = Task { try await harness.controller.networkChanged(trigger: .route) }
        await gate.wait()
        #expect(await harness.controller.operation != nil, "baseline: slot held while parked")
        caller.cancel()
        await settle()
        let held = await harness.controller.operation != nil
        #expect(held, "slot released while the maintenance operation is still parked in routes.install")
        await gate.release(); _ = await caller.result
    }

    @Test
    func `B timer driven captive close keeps the slot`() async throws {
        let gate = StepGate(point: .closeCaptive)
        let harness = try ControllerHarness(gate: gate); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
        for _ in 0 ..< 2000 where !harness.clock.pendingSleeps.contains(.seconds(30)) {
            await Task.yield()
        }
        try #require(harness.clock.pendingSleeps.contains(.seconds(30)))
        harness.clock.advance(.seconds(30))
        await gate.wait()
        await settle()
        let held = await harness.controller.operation != nil
        #expect(held, "slot released while performCloseCaptive is parked at the closeCaptive checkpoint")
        await gate.release()
        while await harness.controller.operation != nil, !Task.isCancelled {
            await Task.yield()
        }
    }

    @Test
    func `C engine death delivered on the event stream keeps the slot`() async throws {
        let gate = StepGate(point: .reconcileBlocking)
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let engine = try #require(await harness.ports.engine)
        await harness.ports.suspend(using: gate)
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        await gate.wait()
        await settle()
        let held = await harness.controller.operation != nil
        #expect(held, "slot released while failStart cleanup is parked in the error policy load")
        await gate.release()
        while await harness.controller.operation != nil, !Task.isCancelled {
            await Task.yield()
        }
    }
}
