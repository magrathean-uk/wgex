// SPDX-License-Identifier: MIT
import Foundation
import Security
import Testing
import WGEXCore
import WGEXProfileStore

/// Lab-only. Never executed by swift test or by the host build verification.
@Suite(.enabled(if: HostedTestGate.enabled))
private struct HostedSecretStoreTests {
    @Test
    func `signed hosted Keychain lifecycle`() async throws {
        let host = Bundle.main.bundleIdentifier ?? ""
        try #require(host == BuildIdentifiers.current.app)
        var code: SecCode?
        try #require(SecCodeCopySelf([], &code) == errSecSuccess)
        let signedCode = try #require(code)
        var requirement: SecRequirement?
        try #require(SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess)
        try #require(SecCodeCheckValidity(signedCode, [], requirement) == errSecSuccess)
        let store = KeychainSecretStore()
        let id = SecretID(profileID: UUID(), kind: .privateKey)
        let key = try SecretBytes(zeroedCount: 32)
        try await store.store(key, for: id)
        do {
            #expect(try await store.exists(id))
            let loaded = try await store.load(id)
            #expect(loaded.count == 32)
            var replacement = try SecretBytes(zeroedCount: 32)
            replacement.withUnsafeMutableBytes { $0[0] = 7 }
            try await store.replace(id, with: replacement)
            let changed = try await store.load(id)
            let matches = changed.withUnsafeBytes { $0[0] == 7 }
            #expect(matches)
            try await store.delete(id)
            #expect(try await !store.exists(id))
        } catch {
            try? await store.delete(id)
            throw error
        }
    }
}
