// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct RecoveryPresentationTests {
    @Test func `fresh recovery failure explains the reason while preserving the protection verdict`() {
        let status = TunnelStatus(
            phase: .failed(.serviceRecovering, blockedByPolicy: true, needsSecrets: false),
            protection: .blocked, transport: nil, health: .idle, recentEvents: [],
            recoveryFailureReason: .multipleBootProfiles,
        )
        let presentation = ProtectionPresentation(status: status, context: .init(platform: .mac))
        #expect(presentation.verdict == .blocked)
        #expect(presentation.recoveryDetail?.contains(MacStrings.moreThanOneProfileStartsBeforeLogin) == true)
        #expect(presentation.primary == MacStrings.trafficBlocked)
        let stale = ProtectionPresentation(status: status, context: .init(platform: .mac, staleness: .stale(since: Date())))
        #expect(stale.verdict == .stale)
        #expect(!stale.secondary.contains(MacStrings.moreThanOneProfileStartsBeforeLogin))
    }
}
