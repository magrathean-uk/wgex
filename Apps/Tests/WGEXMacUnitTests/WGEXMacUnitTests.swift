// SPDX-License-Identifier: MIT

import Testing
import WGEXCore

/// Hosted bundle identity check; the lab gate also requires a signed app and VM.
@Suite(.enabled(if: HostedTestGate.enabled))
private struct WGEXMacUnitTests {
    @Test
    func `build identifiers are generated for app builds`() {
        #expect(BuildIdentifiers.current.team.count == 10)
    }
}
