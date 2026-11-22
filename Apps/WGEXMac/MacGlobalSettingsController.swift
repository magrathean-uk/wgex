// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol

    /// The daemon decides whether a policy change needs authorisation; the cache is never that authority.
    @MainActor
    public final class MacGlobalSettingsController {
        private let send: (MacGlobalSettings, Data?) async throws -> Void
        private let grant: () async throws -> any SecureInstallGrant

        /// Supplies a typed daemon request and an app-only authorisation grant.
        public init(
            send: @escaping (MacGlobalSettings, Data?) async throws -> Void,
            grant: @escaping () async throws -> any SecureInstallGrant,
        ) {
            self.send = send; self.grant = grant
        }

        /// Returns only acknowledged settings, prompting once if the daemon requests an admin right.
        public func set(_ settings: MacGlobalSettings) async throws -> MacGlobalSettings {
            do { try await send(settings, nil) }
            catch DaemonError.notAuthorised(.adminRightRequired) {
                let authorization = try await grant()
                try await send(settings, authorization.externalForm)
                withExtendedLifetime(authorization) {}
            }
            return settings
        }
    }
#endif
