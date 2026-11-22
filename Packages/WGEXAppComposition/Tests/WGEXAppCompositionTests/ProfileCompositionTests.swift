// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXAppComposition
import WGEXCore
import WGEXProfileStore

private enum Scheme: CaseIterable, Sendable {
    case keychain, identity

    func composition(_ store: FakeSecrets) -> ProfileComposition {
        ProfileComposition(strategy: self == .keychain ? .persistentReferences(store) : .identities(store))
    }
}

private enum WriteFailure: Error { case refused }

@Suite(.timeLimit(.minutes(1)))
private struct ProfileCompositionTests {
    @Test(arguments: Scheme.allCases)
    func `round trip`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        let saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: ProfileStore(container: root))
        let loaded = try await ProfileStore(container: root).load(saved.id)
        #expect(loaded == saved)
        switch scheme {
        case .keychain:
            guard case .keychain = saved.secrets.privateKey else { Issue.record("Wrong reference scheme"); return }
            #expect(saved.original == nil)
        case .identity:
            #expect(saved == parsed.profile)
        }
        let packed = try await composition.load(loaded)
        try expectSameKeys(packed, saved, parsed.secrets, parsed.profile)
        #expect(secrets.count == 1 + saved.secrets.presharedKeys.count)
    }

    @Test(arguments: Scheme.allCases)
    func `failed document write rolls back`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        let store = ProfileStore(container: root, writeHook: { _, _ in throw WriteFailure.refused })
        await #expect(throws: WriteFailure.refused) {
            _ = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        }
        #expect(secrets.count == 0)
        #expect(try await store.list().isEmpty)
    }

    @Test(arguments: Scheme.allCases)
    func `delete after relaunch`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let parsed = try fixture()
        let first = scheme.composition(secrets)
        _ = try await first.commit(parsed.profile, secrets: parsed.secrets, to: ProfileStore(container: root))
        let relaunched = scheme.composition(secrets)
        let store = ProfileStore(container: root)
        let saved = try await store.load(parsed.profile.id)
        try await relaunched.deleteSecrets(of: saved)
        try await store.delete(saved.id)
        #expect(secrets.count == 0)
        #expect(try await store.list().isEmpty)
    }

    @Test(arguments: Scheme.allCases)
    func `delete already missing`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        let saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: ProfileStore(container: root))
        try await secrets.removeAll()
        try await composition.deleteSecrets(of: saved)
        #expect(secrets.count == 0)
    }

    @Test(arguments: Scheme.allCases)
    func `editor reloads from store`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let parsed = try fixture()
        let saved = try await scheme.composition(secrets).commit(
            parsed.profile, secrets: parsed.secrets, to: ProfileStore(container: root),
        )
        let replacement = try SecretBytes(zeroedCount: 32)
        try await secrets.replacePrivateKey(with: SecretBytes(parsing: replacement))
        let reloaded = try await scheme.composition(secrets).load(saved)
        let matchesStore = try reloaded.withKey(saved.secrets.privateKey) { raw in
            replacement.withUnsafeBytes { raw.elementsEqual($0) }
        }
        #expect(matchesStore)
        try await secrets.removeAll()
        await #expect(throws: SecretStoreError.notFound) { _ = try await scheme.composition(secrets).load(saved) }
    }

    @Test
    func `copied secrets own their buffers`() throws {
        let parsed = try fixture()
        let copy = try ProfileComposition.copySecrets(parsed.secrets)
        try expectSameKeys(copy, parsed.profile, parsed.secrets, parsed.profile)
    }

    @Test(arguments: Scheme.allCases)
    func `failed edit preserves previous keys`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        let store = ProfileStore(container: root)
        let saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        let original = try await composition.load(saved)
        let changed = try ParsedSecrets(
            bytes: SecretBytes(zeroedCount: original.references.count * 32), references: original.references,
        )
        let failing = ProfileStore(container: root, writeHook: { _, _ in throw WriteFailure.refused })
        await #expect(throws: WriteFailure.refused) {
            _ = try await composition.commit(
                saved, secrets: changed, to: failing, previous: saved,
                installOrder: scheme == .keychain ? .afterDocument : .beforeDocument,
            )
        }
        #expect(try await store.load(saved.id) == saved)
        let reloaded = try await composition.load(saved)
        try expectSameKeys(reloaded, saved, original, saved)
        #expect(secrets.count == original.references.count)
    }

    @Test(arguments: Scheme.allCases)
    func `failed install restores document and keys`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        let store = ProfileStore(container: root)
        await #expect(throws: WriteFailure.refused) {
            _ = try await composition.commit(
                parsed.profile, secrets: parsed.secrets, to: store,
                installOrder: scheme == .keychain ? .afterDocument : .beforeDocument,
                install: { _ in throw WriteFailure.refused },
            )
        }
        #expect(secrets.count == 0)
        #expect(try await store.list().isEmpty)
    }

    @Test(arguments: Scheme.allCases)
    func `refused edit preserves platform rollback order`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let trace = Mutex<[String]>([])
        let secrets = FakeSecrets(record: { operation in trace.withLock { $0.append(operation) } })
        let composition = scheme.composition(secrets)
        let parsed = try fixture()
        var previous = parsed.profile
        // Retain one existing identity and add a new PSK on edit, exercising both tvOS rollback steps.
        previous.secrets.presharedKeys = [:]
        for index in previous.peers.indices {
            previous.peers[index].hasPresharedKey = false
        }
        var previousBytes = try SecretBytes(zeroedCount: 32)
        try parsed.secrets.withKey(previous.secrets.privateKey) { key in
            previousBytes.withUnsafeMutableBytes { $0.copyMemory(from: key) }
        }
        let previousSecrets = try ParsedSecrets(bytes: previousBytes, references: [previous.secrets.privateKey: 0 ..< 32])
        let store = ProfileStore(container: root, writeHook: { _, _ in
            trace.withLock { $0.append("document-write") }
        })
        let saved = try await composition.commit(previous, secrets: previousSecrets, to: store)
        let original = try await composition.load(saved)
        var edited = parsed.profile
        edited.name = "Edited composition"
        await #expect(throws: WriteFailure.refused) {
            _ = try await composition.commit(
                edited, secrets: parsed.secrets, to: store, previous: saved,
                installOrder: scheme == .keychain ? .afterDocument : .beforeDocument,
                install: { _ in trace.withLock { $0 = ["install-failed"] }; throw WriteFailure.refused },
                rollback: {
                    let restored = try? await store.load(saved.id)
                    #expect(restored == saved)
                    trace.withLock { $0.append("restore-backend") }
                },
            )
        }
        let expected = scheme == .keychain
            ? ["install-failed", "document-write", "restore-backend", "delete-created", "delete-created"]
            : ["install-failed", "delete-created", "restore-replaced", "restore-backend"]
        let actual = trace.withLock { $0 }
        print("rollback-order \(scheme): \(actual.joined(separator: ", "))")
        #expect(actual == expected)
        #expect(try await store.load(saved.id) == saved)
        let reloaded = try await composition.load(saved)
        try expectSameKeys(reloaded, saved, original, saved)
        #expect(secrets.count == original.references.count)
    }

    @Test(arguments: Scheme.allCases)
    func `best effort retirement still attempts other keys`(_ scheme: Scheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let parsed = try fixture()
        let composition = scheme.composition(secrets)
        let saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: ProfileStore(container: root))
        #expect(secrets.count == 2)
        secrets.refusePrivateKeyDeletion()
        await #expect(throws: SecretStoreError.locked) {
            try await composition.deleteSecrets(of: saved, bestEffort: true)
        }
        #expect(secrets.count == 1)
    }

    private func fixture() throws -> ParsedConfiguration {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var bytes = try Array(Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/conf/single-peer-full-tunnel.conf")))
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var parsed = try parseWgQuick(&bytes, name: "Composition")
        parsed.profile.protection.ipv6Policy = .blockOutside
        return parsed
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("wgex-composition-\(UUID().uuidString)")
    }

    private func expectSameKeys(
        _ actual: borrowing ParsedSecrets, _ saved: TunnelProfile, _ expected: borrowing ParsedSecrets, _ source: TunnelProfile,
    ) throws {
        let pairs = [(saved.secrets.privateKey, source.secrets.privateKey)] + source.secrets.presharedKeys.map {
            (saved.secrets.presharedKeys[$0.key] ?? $0.value, $0.value)
        }
        for (storedRef, sourceRef) in pairs {
            let equal = try actual.withKey(storedRef) { left in
                try expected.withKey(sourceRef) { left.elementsEqual($0) }
            }
            #expect(equal)
        }
    }
}
