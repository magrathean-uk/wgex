// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Foundation
    import WGEXCore

    /// Lab builds only. Ad hoc signatures cannot use the data protection Keychain (no access-group
    /// entitlement) and every rebuild changes the cdhash, so a login-keychain item from the previous
    /// build raises an ACL password prompt the lab automation must never answer. The lab guest keeps
    /// its throwaway keys as 0600 files under a 0700 directory instead; production builds do not
    /// compile this type.
    public struct LabFileSecretStore: SecretStore {
        private let directory: URL

        public init(directory: URL) {
            self.directory = directory
        }

        private func url(_ id: SecretID) -> URL {
            directory.appendingPathComponent(id.profileID.uuidString, isDirectory: true)
                .appendingPathComponent(id.kind.rawValue, isDirectory: true)
                .appendingPathComponent(id.id.uuidString + ".key", isDirectory: false)
        }

        private func write(_ secret: borrowing SecretBytes, to file: URL, replacing: Bool) throws(SecretStoreError) {
            var data = secret.withUnsafeBytes { Data($0) }
            defer { data.resetBytes(in: 0 ..< data.count) }
            do {
                try FileManager.default.createDirectory(
                    at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700],
                )
                if !replacing, FileManager.default.fileExists(atPath: file.path) {
                    throw SecretStoreError.duplicate
                }
                if replacing, !FileManager.default.fileExists(atPath: file.path) {
                    throw SecretStoreError.notFound
                }
                try data.write(to: file, options: [.atomic, .completeFileProtection])
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            } catch let error as SecretStoreError { throw error } catch { throw .system(EIO) }
        }

        public func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
            try write(secret, to: url(id), replacing: false)
        }

        public func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
            let file = url(id)
            guard FileManager.default.fileExists(atPath: file.path) else { throw .notFound }
            do {
                var data = try Data(contentsOf: file)
                defer { data.resetBytes(in: 0 ..< data.count) }
                return try SecretBytes(wiping: &data)
            } catch { throw .system(EIO) }
        }

        public func delete(_ id: SecretID) async throws(SecretStoreError) {
            let file = url(id)
            guard FileManager.default.fileExists(atPath: file.path) else { throw .notFound }
            do { try FileManager.default.removeItem(at: file) } catch { throw .system(EIO) }
        }

        public func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
            try write(secret, to: url(id), replacing: true)
        }

        public func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
            FileManager.default.fileExists(atPath: url(id).path)
        }
    }
#endif
