// SPDX-License-Identifier: MIT
import Foundation
import Security
import Testing
import WGEXCore
@testable import WGEXProfileStore

/// Status-only fakes: these tests never call Security and never touch any keychain (P1-21).
private struct KeychainSecretStoreRemovalTests {
    private static var expected: [CFString: Any] {
        var query = KeychainSecretStore.query(SecretID(profileID: UUID(), kind: .privateKey))
        query.removeValue(forKey: kSecAttrAccount)
        return query
    }

    @Test
    func `the selector is the item query without the account and asks for no data`() {
        let query = KeychainSecretStore.deleteAllQuery()
        #expect((query as NSDictionary).isEqual(Self.expected as NSDictionary))
        #expect(query[kSecAttrAccount] == nil)
        #expect(query[kSecAttrService] as? String == BuildIdentifiers.base)
        #expect(query[kSecReturnData] == nil)
        #expect(query[kSecReturnPersistentRef] == nil)
        #expect(query[kSecValueData] == nil)
        #expect(query[kSecMatchLimit] == nil)
    }

    @Test(arguments: [errSecSuccess, errSecItemNotFound])
    func `deletion then a metadata lookup that finds nothing is success`(status: OSStatus) throws {
        var calls: [String] = []
        try KeychainSecretStore.deleteAll(delete: { received in
            #expect((received as NSDictionary).isEqual(Self.expected as NSDictionary))
            calls.append("delete")
            return status
        }, lookup: { received in
            #expect((received as NSDictionary).isEqual(Self.expected as NSDictionary))
            calls.append("lookup")
            return errSecItemNotFound
        })
        #expect(calls == ["delete", "lookup"])
    }

    @Test
    func `an item left behind cannot report success`() {
        #expect(throws: SecretStoreError.unavailable) {
            try KeychainSecretStore.deleteAll(delete: { _ in errSecSuccess }, lookup: { _ in errSecSuccess })
        }
    }

    @Test
    func `a failed deletion throws its mapped error and skips the lookup`() {
        #expect(throws: SecretStoreError.system(errSecIO)) {
            try KeychainSecretStore.deleteAll(delete: { _ in errSecIO }, lookup: { _ in
                Issue.record("looked up after a failed deletion"); return errSecItemNotFound
            })
        }
        #expect(throws: SecretStoreError.locked) {
            try KeychainSecretStore.deleteAll(delete: { _ in errSecInteractionNotAllowed }, lookup: { _ in errSecItemNotFound })
        }
    }

    @Test
    func `a locked keychain during the lookup is reported as locked`() {
        #expect(throws: SecretStoreError.locked) {
            try KeychainSecretStore.deleteAll(delete: { _ in errSecSuccess }, lookup: { _ in errSecInteractionNotAllowed })
        }
    }
}
