// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct RecoveryCopyCombinationsTests {
    @Test(arguments: [
        (RecoveryFailureReason.noPrimaryInterface, MacStrings.recoveryNoPrimaryInterface),
        (.profileUnavailable, MacStrings.recoveryProfileUnavailable),
        (.multipleBootProfiles, MacStrings.moreThanOneProfileStartsBeforeLogin),
        (.resolverUnavailable, MacStrings.recoveryResolverUnavailable),
        (.monitorStartFailed, MacStrings.recoveryMonitorStartFailed),
        (.reconciliationFailed, MacStrings.recoveryReconciliationFailed),
        (.intentStartFailed, MacStrings.recoveryIntentStartFailed),
        (.blockingPolicyFailed, MacStrings.recoveryBlockingPolicyFailed),
        (.secureInstallRequired, MacStrings.secureInstallIsNotComplete),
    ])
    func `each recovery reason has its own catalogue explanation`(_ reason: RecoveryFailureReason, _ expected: String) {
        var status = TunnelStatus.idle
        status.recoveryFailureReason = reason
        #expect(ProtectionPresentation(status: status).recoveryDetail?.contains(expected) == true)
    }

    @Test(
        arguments: [
            ProtectionState.protected,
            .blocked,
            .unprotected,
            .unknown,
            .unsupported,
            .captiveWindow(expires: Date(timeIntervalSince1970: 1000)),
        ],
        RecoveryFailureReason.allTestReasons,
    )
    func `recovery fragments have punctuation and an independent reason`(_ protection: ProtectionState, _ reason: RecoveryFailureReason) {
        var status = TunnelStatus.idle
        status.protection = protection; status.recoveryFailureReason = reason
        let view = ProtectionPresentation(status: status)
        #expect(view.secondary.hasSuffix("."))
        #expect(!view.secondary.contains("  "))
        #expect(view.recoveryDetail?.hasSuffix(".") == true)
        #expect(view.recoveryDetail?.isEmpty == false)
        #expect(!view.secondary.contains("tunnel Service"))
    }
}

private extension RecoveryFailureReason {
    nonisolated static var allTestReasons: [Self] {
        [
            .noPrimaryInterface,
            .profileUnavailable,
            .multipleBootProfiles,
            .resolverUnavailable,
            .monitorStartFailed,
            .reconciliationFailed,
            .intentStartFailed,
            .blockingPolicyFailed,
            .secureInstallRequired,
        ]
    }
}
