// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonCore
import WGEXProfileStore

/// Owns one fixture wrapping key in wiped SecretBytes; never opens a Keychain.
public final class InMemoryDaemonKeyProvider: DaemonKeyRemoving {
    private struct Storage: ~Copyable, Sendable { var key: SecretBytes; var removed = false }
    private let storage: Mutex<Storage>

    /// Creates the inert fixture with explicitly supplied state.
    public init(key: consuming SecretBytes) throws {
        guard key.count == 32 else { throw SecretStoreError.unavailable }
        storage = Mutex(Storage(key: key))
    }

    /// Returns an explicit copy of the fixture key in wiped SecretBytes.
    public func wrappingKey() throws -> SecretBytes {
        try storage.withLock { value in
            guard !value.removed else { throw SecretStoreError.notFound }
            return try SecretBytes(parsing: value.key)
        }
    }

    /// Uninstall: the fixture key is gone from here on; removing it twice succeeds.
    public func removeWrappingKey() throws {
        storage.withLock { $0.removed = true }
    }

    /// Whether `removeWrappingKey` ran.
    public var isRemoved: Bool {
        storage.withLock { $0.removed }
    }
}
