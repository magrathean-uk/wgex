// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

@Suite(.enabled(if: HostedTestGate.enabled))
private struct HostedServiceControllerTests {
    private struct VM: SysctlReading {
        func integer(named _: String) -> Int64? {
            1
        }
    }

    @Test
    func `hosted service state uses injected operations`() async {
        // Even this hosted source never registers a daemon or opens approval UI.
        let controller = ServiceController(
            operations: .init(register: {}, unregister: {}, status: { .requiresApproval }, openApproval: {}),
            sysctl: VM(), isDebugBuild: true,
        )
        var state = controller.state.makeAsyncIterator()
        #expect(await state.next() == .requiresApproval)
    }
}
