// SPDX-License-Identifier: MIT

import Testing
import WGEXPairing

private struct PairingServiceTests {
    @Test
    func `bonjour type matches the Info.plist key`() {
        #expect(PairingService.bonjourType == "_wgex-pair._tcp")
    }
}
