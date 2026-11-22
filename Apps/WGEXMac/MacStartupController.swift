// SPDX-License-Identifier: MIT

#if os(macOS)
    import WGEXCore
    import WGEXUI

    /// Coordinates the daemon intent and system login item before publishing a cached choice.
    @MainActor
    public final class MacStartupController {
        private let saveDaemon: (TunnelProfile, MacStartupOption) async throws -> Void
        private let setLoginItem: (Bool) async throws -> Void
        private let saveDocument: (TunnelProfile) async throws -> Void
        private let loadProfiles: () async throws -> [TunnelProfile]

        /// Injects daemon, login-item and storage operations.
        public init(
            saveDaemon: @escaping (TunnelProfile, MacStartupOption) async throws -> Void,
            setLoginItem: @escaping (Bool) async throws -> Void,
            saveDocument: @escaping (TunnelProfile) async throws -> Void,
            loadProfiles: @escaping () async throws -> [TunnelProfile] = { [] },
        ) {
            self.saveDaemon = saveDaemon; self.setLoginItem = setLoginItem; self.saveDocument = saveDocument
            self.loadProfiles = loadProfiles
        }

        /// Commits an exclusive startup choice, restoring the previous choice if a later step fails.
        public func save(_ profile: TunnelProfile, option: MacStartupOption) async throws {
            var updated = profile
            updated.macOptions = option.profileOptions
            let otherLogin = try await loadProfiles().contains { $0.id != profile.id && $0.macOptions.autoConnectAtLogin }
            do {
                try await saveDaemon(updated, option)
                try await applyLoginItem(otherLogin || option == .login)
                try await saveDocument(updated)
            } catch {
                let previous = MacStartupOption(options: profile.macOptions)
                try? await saveDaemon(profile, previous)
                try? await applyLoginItem(otherLogin || previous == .login)
                try? await saveDocument(profile)
                throw error
            }
        }

        /// Deleting the final login profile also removes the app-wide login entry.
        public func synchronizeLoginItem() async throws {
            try await applyLoginItem(loadProfiles().contains { $0.macOptions.autoConnectAtLogin })
        }

        private func applyLoginItem(_ enabled: Bool) async throws {
            do { try await setLoginItem(enabled) }
            catch ServiceError.system { throw MacWorkflowError.loginItem }
        }
    }
#endif
