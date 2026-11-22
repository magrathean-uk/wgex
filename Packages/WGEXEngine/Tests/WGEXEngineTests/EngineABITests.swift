// SPDX-License-Identifier: MIT
#if WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
#else
    import CWGEXEngine
#endif
import Testing
import WGEXEngine
import WGEXEngineInterface

private struct EngineABITests {
    @Test
    func `ABI validation uses the imported header version and a distinct mismatch`() throws {
        try EngineActor.validateABIVersion(Int32(WGEX_ABI_VERSION))
        #expect(throws: EngineError.abiMismatch) { try EngineActor.validateABIVersion(Int32(WGEX_ABI_VERSION) + 1) }
    }
}
