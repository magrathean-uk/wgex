// SPDX-License-Identifier: MIT

import Foundation
import Security
import Testing
import WGEXCore
@testable import WGEXProfileStore

private struct SecretStoreTests {
    @Test
    func `store load replace and delete retain no Foundation secret buffers`() async throws {
        let store: any SecretStore = InMemorySecretStore()
        let id = SecretID(profileID: UUID(), kind: .privateKey)
        let first = try Self.generatedSecret()
        try await store.store(SecretBytes(parsing: first), for: id)
        #expect(try await store.exists(id))
        let loaded = try await store.load(id)
        let secretComparison1 = loaded.constantTimeEquals(first)
        #expect(secretComparison1)
        let replacement = try Self.generatedSecret()
        try await store.replace(id, with: SecretBytes(parsing: replacement))
        let replaced = try await store.load(id)
        let secretComparison2 = replaced.constantTimeEquals(replacement)
        #expect(secretComparison2)
        // A returned buffer remains independently owned after the stored buffer has been replaced.
        let secretComparison3 = loaded.constantTimeEquals(first)
        #expect(secretComparison3)
        try await store.delete(id)
        #expect(try await !store.exists(id))
        await #expect(throws: SecretStoreError.notFound) { _ = try await store.load(id) }
        await #expect(throws: SecretStoreError.notFound) { try await store.delete(id) }
        await #expect(throws: SecretStoreError.notFound) { try await store.replace(id, with: Self.generatedSecret()) }
    }

    @Test
    func `duplicate store preserves existing bytes and printable output is redacted`() async throws {
        let store = InMemorySecretStore()
        let id = SecretID(profileID: UUID(), kind: .presharedKey)
        let first = try Self.generatedSecret()
        try await store.store(SecretBytes(parsing: first), for: id)
        await #expect(throws: SecretStoreError.duplicate) { try await store.store(Self.generatedSecret(), for: id) }
        let loaded = try await store.load(id)
        let secretComparison4 = loaded.constantTimeEquals(first)
        #expect(secretComparison4)
        #expect(String(describing: store) == "InMemorySecretStore(redacted)")
        #expect(String(reflecting: store) == "InMemorySecretStore(redacted)")
        // Public errors contain only known categories, never material from the generated key.
        let errors: [SecretStoreError] = [.locked, .notFound, .duplicate, .system(-1), .unavailable]
        for error in errors {
            let text = String(describing: error)
            #expect(!text.contains("bytes")); #expect(!text.contains("Data"))
            #expect(text.count < 80)
            Self.expectNoSecret(first, in: text)
            Self.expectNoSecret(first, in: String(reflecting: error))
        }
        Self.expectNoSecret(first, in: String(describing: store))
        Self.expectNoSecret(first, in: String(reflecting: store))
        #expect(String(describing: SecretBytes.self) == "SecretBytes")
    }

    @Test
    func `atomic replacement under concurrent loads never exposes partial or missing bytes`() async throws {
        let store = InMemorySecretStore()
        let id = SecretID(profileID: UUID(), kind: .privateKey)
        try await store.store(SecretBytes(zeroedCount: 32), for: id)
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 64 {
                group.addTask {
                    if index.isMultiple(of: 2) {
                        var bytes = try SecretBytes(zeroedCount: 32)
                        _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: UInt8(index)) }
                        try await store.replace(id, with: bytes)
                    } else {
                        let bytes = try await store.load(id)
                        let complete = bytes.withUnsafeBytes { raw in raw.count == 32 && raw.allSatisfy { $0 == raw[0] } }
                        #expect(complete)
                    }
                }
            }
            try await group.waitForAll()
        }
    }

    @Test(arguments: [
        (errSecInteractionNotAllowed, SecretStoreError.locked),
        (errSecNotAvailable, .locked),
        (errSecItemNotFound, .notFound), (errSecDuplicateItem, .duplicate), (errSecAuthFailed, .system(errSecAuthFailed)),
    ])
    func `Keychain status mapping is pure and never calls Security`(status: OSStatus, expected: SecretStoreError) {
        #expect(throws: expected) { try KeychainSecretStore.check(status) }
    }

    @Test
    func `Keychain identity follows the shared service account contract`() {
        let profile = UUID(); let identifier = UUID()
        let id = SecretID(profileID: profile, kind: .carrierCredential, id: identifier)
        #expect(id.account == "\(profile.uuidString)/carrierCredential/\(identifier.uuidString)")
        #expect(throws: Never.self) { try KeychainSecretStore.check(errSecSuccess) }
    }

    private static func expectNoSecret(_ secret: borrowing SecretBytes, in text: String) {
        // Compare output against raw and encoded material without ever creating a secret String.
        let output = Array(text.utf8)
        let leaked = secret.withUnsafeBytes { raw in
            output.count >= raw.count && (0 ... output.count - raw.count).contains { offset in
                output[offset ..< offset + raw.count].elementsEqual(raw)
            }
        }
        #expect(!leaked)
        do {
            var encoded = try SecretBytes(zeroedCount: 44)
            try secret.withUnsafeBytes { source in
                try encoded.withUnsafeMutableBytes { try ByteCodec.encode(source, into: $0, encoding: .base64) }
            }
            let encodedLeak = encoded.withUnsafeBytes { raw in
                output.count >= raw.count && (0 ... output.count - raw.count).contains { offset in
                    output[offset ..< offset + raw.count].elementsEqual(raw)
                }
            }
            #expect(!encodedLeak)
        } catch { Issue.record("Could not encode generated test key for leak scan") }
    }

    private static func generatedSecret() throws -> SecretBytes {
        let key = try PrivateKey.generate()
        var bytes = try SecretBytes(zeroedCount: 32)
        try key.encode(into: &bytes)
        return bytes
    }
}
