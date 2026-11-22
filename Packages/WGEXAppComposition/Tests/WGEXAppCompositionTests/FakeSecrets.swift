// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Synchronization
import WGEXCore
import WGEXProfileStore

/// No Security calls; persistent references encode public identities only.
internal final class FakeSecrets: PersistentReferenceSecretStore {
    private let store = InMemorySecretStore()
    private let refusedDeletion = Mutex<SecretID?>(nil)
    private let ids = Mutex<Set<SecretID>>([])
    private let storeCalls = Mutex(0)
    private let refusedStoreCall = Mutex<Int?>(nil)
    private let refuseEveryDeletion = Mutex(false)
    private let attemptedDeletions = Mutex<[SecretID]>([])
    private let record: @Sendable (String) -> Void

    internal init(record: @escaping @Sendable (String) -> Void = { _ in }) {
        self.record = record
    }

    internal var count: Int {
        ids.withLock { $0.count }
    }

    internal var storeAttempts: Int {
        storeCalls.withLock { $0 }
    }

    internal var deletionAttempts: [SecretID] {
        attemptedDeletions.withLock { $0 }
    }

    internal func refuseStore(afterSuccessfulStores count: Int) {
        let call = storeAttempts + count + 1
        refusedStoreCall.withLock { $0 = call }
    }

    internal func refuseAllDeletions() {
        attemptedDeletions.withLock { $0 = [] }
        refuseEveryDeletion.withLock { $0 = true }
    }

    internal func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
        let call = storeCalls.withLock { $0 += 1; return $0 }
        if refusedStoreCall.withLock({ $0 == call }) {
            throw .locked
        }
        try await store.store(secret, for: id)
        _ = ids.withLock { $0.insert(id) }
    }

    internal func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
        try await store.load(id)
    }

    internal func delete(_ id: SecretID) async throws(SecretStoreError) {
        attemptedDeletions.withLock { $0.append(id) }
        if refuseEveryDeletion.withLock({ $0 }) || refusedDeletion.withLock({ $0 == id }) {
            throw .locked
        }
        try await store.delete(id)
        _ = ids.withLock { $0.remove(id) }
        record("delete-created")
    }

    internal func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
        try await store.replace(id, with: secret)
        record("restore-replaced")
    }

    internal func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
        try await store.exists(id)
    }

    internal func persistentReference(for id: SecretID) async throws(SecretStoreError) -> Data {
        guard try await store.exists(id) else { throw .notFound }
        do { return try JSONEncoder().encode(id) } catch { throw .unavailable }
    }

    internal func load(persistentReference: Data) async throws(SecretStoreError) -> SecretBytes {
        try await load(identity(persistentReference))
    }

    internal func delete(persistentReference: Data) async throws(SecretStoreError) {
        try await delete(identity(persistentReference))
    }

    internal func removeAll() async throws {
        for id in ids.withLock({ $0 }) {
            try await delete(id)
        }
    }

    internal func replacePrivateKey(with secret: consuming SecretBytes) async throws {
        guard let id = ids.withLock({ $0.first { $0.kind == .privateKey } }) else { throw SecretStoreError.notFound }
        try await replace(id, with: secret)
    }

    internal func refusePrivateKeyDeletion() {
        let id = ids.withLock { $0.first { $0.kind == .privateKey } }
        refusedDeletion.withLock { $0 = id }
    }

    private func identity(_ reference: Data) throws(SecretStoreError) -> SecretID {
        do { return try JSONDecoder().decode(SecretID.self, from: reference) } catch { throw .notFound }
    }
}
