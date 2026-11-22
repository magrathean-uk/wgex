// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
import WGEXCore
import WGEXProfileStore

public protocol DaemonKeyProvider: Sendable {
    func wrappingKey() throws -> SecretBytes
}

/// A key provider that can delete its wrapping key (uninstall, M05-T07). Deleting a missing key succeeds.
public protocol DaemonKeyRemoving: DaemonKeyProvider {
    func removeWrappingKey() throws
}

// Owns one wiped key. Used by host tests; no Keychain access.

public protocol TunnelSecretStoring: Sendable {
    func saveBundle(_ bytes: consuming SecretBytes, profileID: UUID) async throws
    func loadBundle(profileID: UUID) async throws -> SecretBytes
    func deleteBundle(profileID: UUID) async throws
    /// The profile ids of every bundle on disk, for the startup sweep of unclaimed bundles (M05-T02).
    func storedBundleProfileIDs() async throws -> [UUID]
    /// Uninstall (M05-T07): the daemon's sealed copies of profile secrets.
    func removeAllSecrets() async throws
    /// Uninstall (M05-T07): every bundle kept for on-demand and start-before-login.
    func removeAllBundles() async throws
    /// Uninstall (M05-T07): the wrapping key, once nothing sealed with it remains.
    func removeWrappingKey() async throws
}

public extension TunnelSecretStoring {
    /// A store that cannot list its bundles offers none to the startup sweep, which then removes nothing.
    func storedBundleProfileIDs() async throws -> [UUID] {
        []
    }

    /// Uninstall (M05-T07): the daemon's sealed copies of profile secrets. A store that keeps none has nothing to remove.
    func removeAllSecrets() async throws {}

    /// Uninstall (M05-T07): every bundle this store lists.
    func removeAllBundles() async throws {
        for id in try await storedBundleProfileIDs() {
            try await deleteBundle(profileID: id)
        }
    }

    /// Uninstall (M05-T07): the wrapping key, once nothing sealed with it remains. A store without one has nothing to remove.
    func removeWrappingKey() async throws {}
}

/// Authenticated encrypted blobs only. Neither filenames nor metadata contain key material.
/// Foundation/CryptoKit plaintext copies are bounded to one call and explicitly wiped where mutable.
public actor DaemonSecretStore: SecretStore, TunnelSecretStoring {
    private let directory: StateDirectory
    private let provider: any DaemonKeyProvider
    private let bundles: StateDirectory
    private let observeBundle: @Sendable (borrowing SecretBytes) throws -> Void

    public init(
        directory: StateDirectory,
        keyProvider: any DaemonKeyProvider,
        observeBundle: @escaping @Sendable (borrowing SecretBytes) throws -> Void = { _ in },
    ) throws {
        self.directory = try directory.directory("secrets"); bundles = try self.directory.directory("bundles"); provider = keyProvider
        self.observeBundle = observeBundle
    }

    public func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
        do {
            guard try directory.read(filename(id)) == nil else { throw SecretStoreError.duplicate }
            try seal(secret, id: id)
        } catch { throw Self.map(error) }
    }

    public func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
        do {
            guard try directory.read(filename(id)) != nil else { throw SecretStoreError.notFound }
            try seal(secret, id: id)
        } catch { throw Self.map(error) }
    }

    public func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
        do { return try open(id, directory: directory) } catch { throw Self.map(error) }
    }

    public func delete(_ id: SecretID) async throws(SecretStoreError) {
        do { try directory.remove(filename(id)) }
        catch { throw Self.map(error) }
    }

    public func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
        do { return try directory.read(filename(id)) != nil }
        catch { throw Self.map(error) }
    }

    public func saveBundle(_ bytes: consuming SecretBytes, profileID: UUID) async throws {
        try? observeBundle(bytes)
        try seal(bytes, id: Self.bundleID(profileID), target: bundles)
    }

    public func loadBundle(profileID: UUID) async throws -> SecretBytes {
        let bytes = try open(Self.bundleID(profileID), directory: bundles)
        try? observeBundle(bytes)
        return bytes
    }

    public func deleteBundle(profileID: UUID) async throws {
        try bundles.remove(filename(Self.bundleID(profileID)))
    }

    /// Only names this store writes for a bundle count; anything else in the directory is not a bundle and is ignored.
    public func storedBundleProfileIDs() async throws -> [UUID] {
        try bundles.filenames().compactMap { name in
            guard let id = UUID(uuidString: String(name.prefix(36))), filename(Self.bundleID(id)) == name else { return nil }
            return id
        }
    }

    /// Uninstall: every sealed secret copy, and anything else in the secrets directory except the bundles directory.
    public func removeAllSecrets() async throws {
        for name in try directory.filenames() where name != "bundles" {
            try directory.remove(name)
        }
    }

    /// Uninstall: every file in the bundles directory, listed bundle or not.
    public func removeAllBundles() async throws {
        try bundles.removeFiles()
    }

    /// Uninstall: refused while anything sealed with the key is left, so a retry never strands ciphertext without its key.
    public func removeWrappingKey() async throws {
        let sealedLeft = try !directory.filenames().allSatisfy { $0 == "bundles" } || !bundles.filenames().isEmpty
        guard !sealedLeft, let removable = provider as? any DaemonKeyRemoving else { throw SecretStoreError.unavailable }
        try removable.removeWrappingKey()
    }

    private func seal(_ bytes: borrowing SecretBytes, id: SecretID, target: StateDirectory? = nil) throws {
        let key = try wrappingKey()
        let sealed = try key.withUnsafeBytes { rawKey in
            try bytes.withUnsafeBytes { raw in
                try AES.GCM.seal(raw, using: SymmetricKey(data: rawKey), authenticating: Data(id.account.utf8))
            }
        }
        guard let combined = sealed.combined else { throw SecretStoreError.unavailable }
        try (target ?? directory).replace(filename(id), with: combined)
    }

    private func open(_ id: SecretID, directory: StateDirectory) throws -> SecretBytes {
        guard let encrypted = try directory.read(filename(id)) else { throw SecretStoreError.notFound }
        let key = try wrappingKey()
        let box = try AES.GCM.SealedBox(combined: encrypted)
        var plain = try key.withUnsafeBytes { try AES.GCM.open(box, using: SymmetricKey(data: $0), authenticating: Data(id.account.utf8)) }
        defer { plain.resetBytes(in: plain.startIndex ..< plain.endIndex) }
        return try SecretBytes(wiping: &plain)
    }

    private func filename(_ id: SecretID) -> String {
        "\(id.profileID.uuidString)-\(id.kind.rawValue)-\(id.id.uuidString).blob"
    }

    private func wrappingKey() throws -> SecretBytes {
        do { return try provider.wrappingKey() }
        catch SecretStoreError.notFound { throw SecretStoreError.unavailable }
    }

    private static func bundleID(_ profileID: UUID) -> SecretID {
        SecretID(profileID: profileID, kind: .privateKey, id: profileID)
    }

    private static func map(_ error: any Error) -> SecretStoreError {
        (error as? SecretStoreError) ?? .unavailable
    }
}
