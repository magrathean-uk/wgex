// SPDX-License-Identifier: MIT

import Foundation
import Security
import WGEXCore

/// A store whose items can also be addressed by an opaque Keychain persistent reference, the only form the
/// packet-tunnel provider accepts (`SecretRef.keychain`). References are identifiers, not secrets.
public protocol PersistentReferenceSecretStore: SecretStore {
    func persistentReference(for id: SecretID) async throws(SecretStoreError) -> Data
    func load(persistentReference: Data) async throws(SecretStoreError) -> SecretBytes
    func delete(persistentReference: Data) async throws(SecretStoreError)
}

/// Data-protection Keychain implementation. Exercise only from signed hosted bundles (P1-21).
public struct KeychainSecretStore: PersistentReferenceSecretStore {
    public init() {}

    public func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
        var attributes = Self.query(id)
        attributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        try Self.withData(secret) { data throws(SecretStoreError) in
            attributes[kSecValueData] = data
            defer { attributes.removeValue(forKey: kSecValueData) }
            try Self.check(SecItemAdd(attributes as CFDictionary, nil))
        }
    }

    public func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
        try Self.copyBytes(matching: Self.query(id))
    }

    /// The persistent reference of an existing item, for `SecretRef.keychain`. The item's own attributes are unchanged.
    public func persistentReference(for id: SecretID) async throws(SecretStoreError) -> Data {
        var result: CFTypeRef?
        try Self.check(SecItemCopyMatching(Self.persistentReferenceQuery(id) as CFDictionary, &result))
        guard let result, CFGetTypeID(result) == CFDataGetTypeID() else { throw .system(errSecDecode) }
        return Data(referencing: unsafeDowncast(result, to: CFData.self) as NSData)
    }

    public func load(persistentReference: Data) async throws(SecretStoreError) -> SecretBytes {
        try Self.copyBytes(matching: Self.referenceQuery(persistentReference))
    }

    public func delete(persistentReference: Data) async throws(SecretStoreError) {
        try Self.check(SecItemDelete(Self.referenceQuery(persistentReference) as CFDictionary))
    }

    private static func copyBytes(matching base: [CFString: Any]) throws(SecretStoreError) -> SecretBytes {
        var query = base
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        try Self.check(SecItemCopyMatching(query as CFDictionary, &result))
        guard let result, CFGetTypeID(result) == CFDataGetTypeID() else { throw .system(errSecDecode) }
        // The SecItem result owns this allocation. Bridging to Data and mutating would detach on write.
        let data = unsafeDowncast(result, to: CFData.self)
        let count = CFDataGetLength(data)
        let pointer = CFDataGetBytePtr(data)
        defer {
            if let pointer {
                _ = memset_s(UnsafeMutableRawPointer(mutating: pointer), count, 0, count)
            }
        }
        do { return try SecretBytes(copying: UnsafeRawBufferPointer(start: pointer, count: count)) }
        catch { throw .system(errSecAllocate) }
    }

    /// Uninstall (M05-T10): deletes every item of this build's service and access group, whatever its account. Absence is
    /// success; a lookup afterwards (metadata only, never key bytes) must find none.
    public func deleteAll() async throws(SecretStoreError) {
        try Self.deleteAll(delete: { SecItemDelete($0 as CFDictionary) }, lookup: { SecItemCopyMatching($0 as CFDictionary, nil) })
    }

    /// Tests supply status-only fakes; neither adapter can return secret bytes.
    package static func deleteAll(
        delete: ([CFString: Any]) -> OSStatus, lookup: ([CFString: Any]) -> OSStatus,
    ) throws(SecretStoreError) {
        let query = Self.deleteAllQuery()
        let status = delete(query)
        if status != errSecItemNotFound {
            try Self.check(status)
        }
        let remaining = lookup(query)
        if remaining == errSecItemNotFound {
            return
        }
        try Self.check(remaining)
        throw .unavailable
    }

    /// The item selector of `query(_:)` without the account: this build's items only, never another app's.
    package static func deleteAllQuery() -> [CFString: Any] {
        var query = Self.query(SecretID(profileID: UUID(), kind: .privateKey))
        query.removeValue(forKey: kSecAttrAccount)
        return query
    }

    public func delete(_ id: SecretID) async throws(SecretStoreError) {
        try Self.check(SecItemDelete(Self.query(id) as CFDictionary))
    }

    public func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
        try Self.withData(secret) { data throws(SecretStoreError) in
            try Self.check(SecItemUpdate(Self.query(id) as CFDictionary, [kSecValueData: data] as CFDictionary))
        }
    }

    public func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
        let status = SecItemCopyMatching(Self.query(id) as CFDictionary, nil)
        if status == errSecItemNotFound {
            return false
        }
        try Self.check(status)
        return true
    }

    /// The item query plus the persistent-reference return; every item attribute is the unchanged `query(_:)`.
    package static func persistentReferenceQuery(_ id: SecretID) -> [CFString: Any] {
        var query = Self.query(id)
        query[kSecReturnPersistentRef] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        return query
    }

    /// Addresses one item by its persistent reference alone.
    package static func referenceQuery(_ reference: Data) -> [CFString: Any] {
        [kSecValuePersistentRef: reference]
    }

    package static func query(_ id: SecretID) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: BuildIdentifiers.base,
            kSecAttrAccount: id.account,
            kSecAttrSynchronizable: false,
        ]
        #if WGEX_LAB_BUILD
        // Ad hoc Lab builds carry no keychain-access-groups entitlement, so the data protection
        // keychain refuses them (errSecMissingEntitlement). The lab guest uses the login keychain
        // with the same item shape; production keeps the access group and data protection.
        #else
            query[kSecAttrAccessGroup] = BuildIdentifiers.current.keychainAccessGroup
            #if os(macOS)
                query[kSecUseDataProtectionKeychain] = true
            #endif
        #endif
        return query
    }

    /// Pure status mapping is testable without calling Security.
    package static func check(_ status: OSStatus) throws(SecretStoreError) {
        switch status {
        case errSecSuccess: return
        case errSecInteractionNotAllowed, errSecNotAvailable: throw .locked
        case errSecItemNotFound: throw .notFound
        case errSecDuplicateItem: throw .duplicate
        default: throw .system(status)
        }
    }

    package static func withData(
        _ secret: borrowing SecretBytes, _ body: (CFData) throws(SecretStoreError) -> Void,
    ) throws(SecretStoreError) {
        try secret.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws(SecretStoreError) in
            guard let data = CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault, raw.baseAddress?.assumingMemoryBound(to: UInt8.self), raw.count, kCFAllocatorNull,
            ) else { throw .system(errSecAllocate) }
            try body(data)
        }
    }
}
