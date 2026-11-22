// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXUI

    private struct MacWorkflowErrorTests {
        @Test func `typed table covers daemon tunnel service and store cases without payloads`() {
            let id = UUID()
            let payload = "untrusted error payload"
            let errors: [any Error] = [
                DaemonError.malformedMessage, DaemonError.messageTooLarge(1), DaemonError.unsupportedProtocolVersion(99),
                DaemonError.notAuthorised(.adminRightRequired), DaemonError.profileNotFound(id), DaemonError.secretsUnavailable,
                DaemonError.downgradeDetected, DaemonError.secureInstallRequired, DaemonError.protectionUnknown(reason: payload),
                DaemonError.busy, DaemonError.rateLimited, DaemonError.unauthorised, DaemonError.handshakeRequired,
                DaemonError.staleGeneration, DaemonError.anotherTunnelActive, DaemonError.disconnected,
                DaemonError.subscriptionLimit, DaemonError.recovering, DaemonError.multipleBootProfiles, DaemonError.tunnel(.timedOut),
                TunnelError.anotherTunnelActive, TunnelError.profileNotFound(id), TunnelError.invalidConfiguration(.invalidProfile),
                TunnelError.serviceRecovering,
                TunnelError.secretsUnavailable, TunnelError.backendUnavailable, TunnelError.permissionDenied,
                TunnelError.timedOut, TunnelError.engine(code: 1), TunnelError.cancelled,
                ServiceError.hostGuard, ServiceError.system(code: 1), ServiceError.unsupported,
                ProfileStoreError.notFound, ProfileStoreError.invalidDocument, ProfileStoreError.unsupportedVersion(99),
                ProfileStoreError.invalidMigration, ProfileStoreError.system(1),
                SecretStoreError.locked, SecretStoreError.notFound, SecretStoreError.duplicate,
                SecretStoreError.system(1), SecretStoreError.unavailable,
                MacWorkflowError.secureInstallRequired, MacWorkflowError.operationInProgress, MacWorkflowError.importSource,
                MacImportSources.Failure.invalid, MacImportSources.Failure.unsupported, MacImportSources.Failure.tooLarge,
            ]
            for error in errors {
                let copy = MacAppErrorCopy.resolve(error)
                #expect(!copy.title.isEmpty)
                #expect(!copy.consequence.isEmpty)
                #expect(!copy.action.isEmpty)
                #expect(!copy.message.contains(payload))
                #expect(!copy.message.contains("not available yet"))
            }
        }

        @Test func `recovering daemon and tunnel errors share actionable recovery copy`() {
            let daemon = MacAppErrorCopy.resolve(DaemonError.recovering)
            let tunnel = MacAppErrorCopy.resolve(TunnelError.serviceRecovering)
            #expect(daemon == tunnel)
            #expect(daemon.title == "Service is recovering")
            #expect(!daemon.consequence.contains("blocked"))
            #expect(MacErrorCopy(.serviceRecovering, protection: .blocked).consequence.contains("blocked"))
            #expect(MacErrorCopy(.serviceRecovering, protection: .unprotected).consequence == MacStrings.trafficCanLeaveOutsideTheTunnel)
            #expect(daemon.action.contains("Wait"))
            #expect(daemon != MacErrorCopy(.service))
        }
    }
#endif
