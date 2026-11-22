// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXTesting

private struct FakeServiceControllerTests {
    @Test
    func `register moves to approval and observers see it`() async throws {
        let controller = FakeServiceController()
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == .notRegistered)
        try await controller.register()
        #expect(await states.next() == .requiresApproval)
        controller.transition(to: .enabled)
        #expect(await states.next() == .enabled)
        controller.openApproval()
        #expect(controller.calls == [.register, .openApproval])
    }

    @Test
    func `register can fail through a fault`() async {
        let controller = FakeServiceController()
        controller.faults.arm("register", error: ServiceError.hostGuard)
        await #expect(throws: ServiceError.hostGuard) { try await controller.register() }
    }
}
