// SPDX-License-Identifier: MIT
import Foundation
import Security
import Testing
import WGEXCore
@testable import WGEXProfileStore

/// Pure query construction only: these tests never call Security and never touch any keychain (P1-21).
private struct KeychainPersistentReferenceTests {
    private let id = SecretID(profileID: UUID(), kind: .privateKey)

    @Test
    func `item query keeps its attributes and gains no accessibility class`() {
        var expected: [String: String] = [
            kSecClass as String: "\(kSecClassGenericPassword)",
            kSecAttrService as String: BuildIdentifiers.base,
            kSecAttrAccount as String: id.account,
            kSecAttrSynchronizable as String: "false",
        ]
        #if !WGEX_LAB_BUILD
            expected[kSecAttrAccessGroup as String] = BuildIdentifiers.current.keychainAccessGroup
            #if os(macOS)
                expected[kSecUseDataProtectionKeychain as String] = "true"
            #endif
        #endif
        let actual = Dictionary(uniqueKeysWithValues: KeychainSecretStore.query(id).map { ("\($0.key)", "\($0.value)") })
        #expect(actual == expected)
    }

    @Test
    func `persistent reference query is the item query plus the reference return`() {
        let base = KeychainSecretStore.query(id) as NSDictionary
        let query = KeychainSecretStore.persistentReferenceQuery(id)
        #expect(query[kSecReturnPersistentRef] as? Bool == true)
        #expect(query[kSecMatchLimit] as? String == kSecMatchLimitOne as String)
        #expect(query[kSecReturnData] == nil)
        var rest = query
        rest.removeValue(forKey: kSecReturnPersistentRef)
        rest.removeValue(forKey: kSecMatchLimit)
        #expect((rest as NSDictionary).isEqual(base))
    }

    @Test
    func `reference queries address the item only by its persistent reference`() {
        let reference = Data([1, 2, 3, 4])
        let query = KeychainSecretStore.referenceQuery(reference)
        #expect(Set(query.keys) == [kSecValuePersistentRef])
        #expect(query[kSecValuePersistentRef] as? Data == reference)
    }
}
