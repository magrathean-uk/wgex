// SPDX-License-Identifier: MIT

import CWGEXSysShim
import Darwin
import Testing

/// Every call uses descriptor -1, so the kernel rejects it before touching any
/// interface: these tests never change network state.
private struct SysShimTests {
    private static var expectedError: Int32 {
        #if os(macOS)
            EBADF
        #else
            ENOTSUP
        #endif
    }

    @Test
    func `invalid descriptors are rejected without side effects`() {
        var alias6 = [UInt8](repeating: 0, count: 256)
        let address: [UInt8] = [10, 77, 0, 2]
        #expect(wgex_interface_mtu(-1, "utun9", 1400) == Self.expectedError)
        #expect(wgex_interface_address(-1, "utun9", address, 4, 24, 0) == Self.expectedError)
        let result = alias6.withUnsafeMutableBytes { wgex_sioc_aifaddr_in6(-1, $0.baseAddress) }
        #expect(result == Self.expectedError)
    }

    @Test
    func `null requests are refused`() {
        #if os(macOS)
            #expect(wgex_interface_mtu(-1, nil, 1400) == EINVAL)
            #expect(wgex_interface_mtu(-1, "utun9", 9000) == EINVAL)
            #expect(wgex_interface_address(-1, "utun9", nil, 4, 24, 0) == EINVAL)
        #endif
        #expect(WGEX_SYSSHIM_ABI_VERSION == 1)
    }
}
