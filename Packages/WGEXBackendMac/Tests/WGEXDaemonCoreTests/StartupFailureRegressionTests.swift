// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct StartupFailureRegressionTests {
    @Test
    func `restoring a boot intent preserves intentStartFailed after route install failure`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let controller = try harness.replacementController()
        harness.trace.fail(at: "routes.install")
        await #expect(throws: DaemonFailure.startup(.intentStartFailed)) { try await controller.reconcileAtStartup() }
        #expect(await controller.status.recoveryFailureReason == .intentStartFailed)
    }

    private struct FailAfterResolution: DaemonStepObserving {
        func before(_ step: DaemonStep, generation: Generation) async throws {
            if step == .allowEndpoints {
                throw DaemonFailure.portNoAnswer
            }
        }
    }

    @Test
    func `a canonical failure at the last resolve step publishes resolverUnavailable`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let controller = try harness.replacementController(steps: FailAfterResolution())
        await #expect(throws: DaemonFailure.startup(.resolverUnavailable)) { try await controller.reconcileAtStartup() }
        #expect(try DaemonJournal(directory: harness.directory).snapshot().entries.last?.step == .resolve)
        #expect(await controller.status.recoveryFailureReason == .resolverUnavailable)
    }
}
