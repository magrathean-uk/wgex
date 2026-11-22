// SPDX-License-Identifier: MIT

import Testing
import WGEXEngine

private struct EngineLinkageTests {
    @Test
    func `Go provenance is linked`() {
        #expect(EngineLinkage.current == .goEngine)
        #expect(EngineLinkage.provenance["engine_commit"] == "b3bc704ef0ee21a36298601a9e1e5ff90377ac52")
    }
}
