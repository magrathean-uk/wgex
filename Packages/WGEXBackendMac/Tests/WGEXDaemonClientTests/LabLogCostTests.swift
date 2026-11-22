// SPDX-License-Identifier: MIT
import Synchronization
import Testing
@testable import WGEXDaemonClient

private struct LabLogCostTests {
    @Test
    func `lab diagnostic arguments are evaluated only in lab builds`() {
        let (_, _, _, client) = clientFixture(), count = Mutex(0)
        func message() -> String {
            count.withLock { $0 += 1 }; return "Lab diagnostic event"
        }
        client.labLog(message())
        #if WGEX_LAB_BUILD
            #expect(count.withLock { $0 } == 1)
        #else
            #expect(count.withLock { $0 } == 0)
        #endif
    }
}
