// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

private struct KeychainHostedTests {
    #if WGEX_HOSTED_TESTS
        @Test
        func `hosted signed Keychain round trip and atomic replacement`() async throws {
            let store = KeychainSecretStore()
            let id = SecretID(profileID: UUID(), kind: .privateKey)
            let key = try PrivateKey.generate()
            var bytes = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &bytes)
            try await store.store(SecretBytes(parsing: bytes), for: id)
            do {
                #expect(try await store.exists(id))
                let loaded = try await store.load(id)
                let secretComparison1 = loaded.constantTimeEquals(bytes)
                #expect(secretComparison1)
                let next = try PrivateKey.generate()
                var replacement = try SecretBytes(zeroedCount: 32)
                try next.encode(into: &replacement)
                try await store.replace(id, with: SecretBytes(parsing: replacement))
                let replaced = try await store.load(id)
                let secretComparison2 = replaced.constantTimeEquals(replacement)
                #expect(secretComparison2)
                try await store.delete(id)
                #expect(try await !store.exists(id))
            } catch {
                try? await store.delete(id)
                throw error
            }
        }

        @Test
        func `hosted persistent reference loads and deletes the stored item`() async throws {
            let store = KeychainSecretStore()
            let id = SecretID(profileID: UUID(), kind: .presharedKey)
            var bytes = try SecretBytes(zeroedCount: 32)
            try PrivateKey.generate().encode(into: &bytes)
            try await store.store(SecretBytes(parsing: bytes), for: id)
            do {
                let reference = try await store.persistentReference(for: id)
                #expect(!reference.isEmpty)
                let loaded = try await store.load(persistentReference: reference)
                let matches = loaded.constantTimeEquals(bytes)
                #expect(matches)
                try await store.delete(persistentReference: reference)
                #expect(try await !store.exists(id))
                await #expect(throws: SecretStoreError.notFound) { _ = try await store.load(persistentReference: reference) }
            } catch {
                try? await store.delete(id)
                throw error
            }
        }
    #else
        @Test(
            .disabled("Requires a signed hosted bundle with Keychain entitlements; swift test must not access the host Keychain (P1-21)."),
        )
        func `hosted signed Keychain round trip and atomic replacement`() {}

        @Test(
            .disabled("Requires a signed hosted bundle with Keychain entitlements; swift test must not access the host Keychain (P1-21)."),
        )
        func `hosted persistent reference loads and deletes the stored item`() {}
    #endif
}
