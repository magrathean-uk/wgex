// SPDX-License-Identifier: MIT

import Testing
import WGEXNEClient

private struct TunnelProviderIdentityTests {
    @Test
    func `provider identifier is the tunnel extension`() {
        #expect(TunnelProviderIdentity.providerBundleIdentifier.hasSuffix(".tunnel"))
    }
}
