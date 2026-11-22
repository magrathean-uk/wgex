// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import WGEXCore

/// Public identity of a secret; it contains no key material.
public struct SecretID: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable { case privateKey, presharedKey, carrierCredential }
    public let profileID: UUID
    public let kind: Kind
    public let id: UUID

    public init(profileID: UUID, kind: Kind, id: UUID = UUID()) {
        self.profileID = profileID; self.kind = kind; self.id = id
    }

    public var account: String {
        "\(profileID.uuidString)/\(kind.rawValue)/\(id.uuidString)"
    }
}

/// Failures contain only categories and numeric system status, never secret bytes.
public enum SecretStoreError: Error, Sendable, Equatable {
    case locked, notFound, duplicate
    case system(Int32)
    /// This operation is unavailable in the selected store.
    case unavailable
}

/// Each replace updates an existing item atomically; it never deletes then adds.
/// Loads return uniquely owned, wiped buffers. Operations never expose a secret string.
public protocol SecretStore: Sendable {
    func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError)
    func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes
    func delete(_ id: SecretID) async throws(SecretStoreError)
    func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError)
    func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool
}

/// In-memory store for tests and previews. The mutex owns all retained secret buffers.
public final class InMemorySecretStore: SecretStore, CustomStringConvertible, CustomDebugStringConvertible {
    private struct Item: ~Copyable, Sendable {
        var bytes: SecretBytes
    }

    /// A noncopyable buffer is held behind a reference solely to fit Dictionary's Copyable value constraint.
    private final class Buffer: Sendable {
        private let item: Mutex<Item>
        init(_ bytes: consuming SecretBytes) {
            item = Mutex(Item(bytes: bytes))
        }

        func copy() throws -> SecretBytes {
            try item.withLock { try SecretBytes(parsing: $0.bytes) }
        }
    }

    private let items = Mutex<[SecretID: Buffer]>([:])
    public init() {}
    public var description: String {
        "InMemorySecretStore(redacted)"
    }

    public var debugDescription: String {
        description
    }

    public func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
        let buffer = Buffer(secret)
        try items.withLock { items throws(SecretStoreError) in
            guard items[id] == nil else { throw .duplicate }
            items[id] = buffer
        }
    }

    public func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
        do {
            return try items.withLock { items -> SecretBytes in
                guard let buffer = items[id] else { throw SecretStoreError.notFound }
                return try buffer.copy()
            }
        } catch let error as SecretStoreError { throw error }
        catch { throw .system(ENOMEM) }
    }

    public func delete(_ id: SecretID) async throws(SecretStoreError) {
        try items.withLock { items throws(SecretStoreError) in
            guard items.removeValue(forKey: id) != nil else { throw .notFound }
        }
    }

    public func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
        let buffer = Buffer(secret)
        try items.withLock { items throws(SecretStoreError) in
            guard items[id] != nil else { throw .notFound }
            items[id] = buffer
        }
    }

    public func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
        items.withLock { $0[id] != nil }
    }
}
