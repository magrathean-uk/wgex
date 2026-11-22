// SPDX-License-Identifier: MIT

import Testing
import WGEXActivityShared

private struct ActivitySupportTests {
    @Test
    func `live activities exist only on iOS`() {
        #if os(iOS)
            #expect(ActivitySupport.isAvailable)
        #else
            #expect(!ActivitySupport.isAvailable)
        #endif
    }
}
