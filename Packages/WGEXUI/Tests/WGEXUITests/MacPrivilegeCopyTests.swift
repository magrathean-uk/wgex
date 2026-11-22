// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXUI
#if os(macOS)
    import WGEXDaemonProtocol

    private struct MacPrivilegeCopyTests {
        @Test(arguments: [
            (TunnelError.revisionConflict, "Another copy of WGEX changed this tunnel; reload and try again"),
            (.busy, "The service is busy; try again in a moment"),
        ])
        func `conflict and busy retain actionable copy across error adapters`(_ error: TunnelError, expected: String) {
            #expect(EventDescription.errorText(error) == expected)
            #expect(MacErrorCopy(tunnel: error).consequence == expected)
            #expect(MacAppErrorCopy.resolve(error).consequence == expected)
            #expect(MacAppErrorCopy.resolve(DaemonError.tunnel(error)).consequence == expected)
        }

        @Test func `unverified DNS cannot claim tunnel resolver protection`() {
            let copy = MacAppErrorCopy.resolve(DaemonProtectionReason.dnsUnverified)
            #expect(copy.consequence == "DNS is not routed through the tunnel")
            #expect(!copy.action.isEmpty)
            #expect(MacAppErrorCopy.resolve(DaemonError.protectionUnknown(reason: "dnsUnverified")) == copy)
        }

        @Test(arguments: [SecureInstallReport.Reason.aclWritable, .wrappingKeyUnavailable, .wrappingKeyRepairFailed])
        func `ACL and wrapping key faults offer secure install repair`(_ reason: SecureInstallReport.Reason) {
            let copy = MacAppErrorCopy.resolve(reason)
            #expect(copy == MacErrorCopy(.secureRequired))
            #expect(copy.title == "Secure install needed")
            #expect(copy.action.contains("Secure Install"))
            #expect(copy.action.contains("Settings"))
        }
    }
#endif
