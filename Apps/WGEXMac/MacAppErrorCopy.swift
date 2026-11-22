// SPDX-License-Identifier: MIT

#if os(macOS)
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXUI

    /// App-only adapters keep storage and daemon dependencies outside the UI library.
    public nonisolated enum MacAppErrorCopy {
        /// Selects fixed copy without rendering associated payloads or system descriptions.
        public static func resolve(_ error: any Error) -> MacErrorCopy {
            if let failure = error as? MacDaemonOperationFailure {
                return failure.copy
            }
            if let error = error as? DaemonError {
                return daemon(error)
            }
            if let error = error as? ProfileStoreError {
                return profileStore(error)
            }
            if let error = error as? SecretStoreError {
                return secretStore(error)
            }
            if let error = error as? MacImportSources.Failure {
                switch error {
                case .invalid, .unsupported, .tooLarge: return MacErrorCopy(.importSource)
                }
            }
            return MacErrorCopy(error: error)
        }

        /// Explains a finite daemon protection reason without exposing protocol payloads.
        public static func resolve(_ reason: DaemonProtectionReason) -> MacErrorCopy {
            switch reason {
            case .dnsUnverified: MacErrorCopy(.dnsUnverified)
            }
        }

        /// Offers secure install for repairable bundle and wrapping-key refusals.
        public static func resolve(_ reason: SecureInstallReport.Reason) -> MacErrorCopy {
            switch reason {
            case .aclWritable, .wrappingKeyUnavailable, .wrappingKeyRepairFailed, .bundleWritable,
                 .notRootOwned: MacErrorCopy(.secureRequired)
            case .notInApplications, .wrongBundle, .identityMismatch, .inspectionFailed: MacErrorCopy(.service)
            }
        }

        private static func daemon(_ error: DaemonError) -> MacErrorCopy {
            switch error {
            case .malformedMessage, .messageTooLarge, .unsupportedProtocolVersion, .handshakeRequired: MacErrorCopy(.protocolMismatch)
            case .notAuthorised, .unauthorised: MacErrorCopy(.permission)
            case .downgradeDetected: MacErrorCopy(.downgrade)
            case .secureInstallRequired: MacErrorCopy(.secureRequired)
            case let .protectionUnknown(reason):
                if let reason = DaemonProtectionReason(rawValue: reason) {
                    resolve(reason)
                } else {
                    MacErrorCopy(.service)
                }
            case .disconnected, .uninstallFailed: MacErrorCopy(.service)
            case .onDemandNotConfigured: MacErrorCopy(.onDemandNotConfigured)
            case .busy, .rateLimited, .staleGeneration, .subscriptionLimit: MacErrorCopy(.busy)
            case .profileNotFound, .secretsUnavailable, .anotherTunnelActive, .recovering, .multipleBootProfiles, .tunnel:
                MacErrorCopy(tunnel: error.tunnelError)
            }
        }

        private static func profileStore(_ error: ProfileStoreError) -> MacErrorCopy {
            switch error {
            case .notFound: MacErrorCopy(.missingProfile)
            case .invalidDocument: MacErrorCopy(.store)
            case .invalidMigration, .unsupportedVersion: MacErrorCopy(.document)
            case .system: MacErrorCopy(.store)
            }
        }

        private static func secretStore(_ error: SecretStoreError) -> MacErrorCopy {
            switch error {
            case .locked, .notFound, .unavailable: MacErrorCopy(.secrets)
            case .duplicate, .system: MacErrorCopy(.store)
            }
        }
    }
#endif
