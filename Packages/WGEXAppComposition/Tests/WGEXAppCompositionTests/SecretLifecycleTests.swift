// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXAppComposition
import WGEXCore
import WGEXProfileStore

private enum StorageScheme: CaseIterable, Sendable {
    case persistentReferences, identities

    func composition(_ store: FakeSecrets) -> ProfileComposition {
        ProfileComposition(strategy: self == .persistentReferences ? .persistentReferences(store) : .identities(store))
    }

    var installOrder: ProfileComposition.InstallOrder {
        self == .persistentReferences ? .afterDocument : .beforeDocument
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct SecretLifecycleTests {
    @Test
    func `iOS editor ignores daemon carrier references in a stored document`() async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = ProfileComposition(strategy: .persistentReferences(secrets))
        let parsed = try fixture()
        let store = ProfileStore(container: root)
        var saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        let carrier = SecretRef.daemonStore(id: UUID())
        saved.secrets.carrierCredentials[TransportID(rawValue: UUID())] = carrier
        try await store.save(saved)
        let document = try await ProfileStore(container: root).load(saved.id)
        let loaded = try await composition.load(document)
        try expectSameKeys(loaded, document, parsed.secrets, parsed.profile)
        #expect(loaded.references.count == 2)
        #expect(loaded.references[carrier] == nil)
        #expect(document.secrets.carrierCredentials.values.contains(carrier))
    }

    @Test
    func `tvOS loads carrier bytes and deduplicates shared references`() async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = ProfileComposition(strategy: .identities(secrets))
        let parsed = try fixture()
        let store = ProfileStore(container: root)
        var saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        let carrierID = UUID()
        let carrier = SecretRef.daemonStore(id: carrierID)
        // Identity loading historically treats every non-private reference as a PSK identity.
        let identity = SecretID(profileID: saved.id, kind: .presharedKey, id: carrierID)
        let expected = try SecretBytes(zeroedCount: 32)
        try await secrets.store(SecretBytes(parsing: expected), for: identity)
        saved.secrets.carrierCredentials[TransportID(rawValue: UUID())] = carrier
        saved.secrets.carrierCredentials[TransportID(rawValue: UUID())] = saved.secrets.privateKey
        try await store.save(saved)
        let document = try await ProfileStore(container: root).load(saved.id)
        let loaded = try await composition.load(document)
        try expectSameKeys(loaded, document, parsed.secrets, parsed.profile)
        let equal = try loaded.withKey(carrier) { raw in expected.withUnsafeBytes { raw.elementsEqual($0) } }
        #expect(equal)
        #expect(loaded.references.count == 3)
        try await composition.deleteSecrets(of: document)
        #expect(secrets.count == 0)
    }

    @Test(arguments: StorageScheme.allCases)
    func `partial staging failure discards the first created key without document or backend effects`(_ scheme: StorageScheme) async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let effects = Mutex<[String]>([])
        let secrets = FakeSecrets()
        let composition = scheme.composition(secrets)
        let store = ProfileStore(container: root, writeHook: { _, _ in effects.withLock { $0.append("document") } })
        let unrelated = try fixture()
        let kept = try await composition.commit(unrelated.profile, secrets: unrelated.secrets, to: store)
        let count = secrets.count
        let calls = secrets.storeAttempts
        let parsed = try fixture()
        effects.withLock { $0 = [] }
        secrets.refuseStore(afterSuccessfulStores: 1)
        await #expect(throws: SecretStoreError.locked) {
            _ = try await composition.commit(
                parsed.profile, secrets: parsed.secrets, to: store, installOrder: scheme.installOrder,
                install: { _ in effects.withLock { $0.append("backend-install") } },
            )
        }
        #expect(secrets.storeAttempts == calls + 2)
        #expect(secrets.count == count)
        #expect(effects.withLock { $0 }.isEmpty)
        #expect(try await store.list() == [kept])
        let reloaded = try await composition.load(kept)
        try expectSameKeys(reloaded, kept, unrelated.secrets, unrelated.profile)
    }

    @Test
    func `successful tvOS edit keeps referenced identities and another profiles keys`() async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = ProfileComposition(strategy: .identities(secrets))
        let store = ProfileStore(container: root)
        let unrelated = try fixture()
        let kept = try await composition.commit(unrelated.profile, secrets: unrelated.secrets, to: store)
        let parsed = try fixture()
        let previous = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        let changed = try ParsedSecrets(bytes: SecretBytes(zeroedCount: 64), references: parsed.secrets.references)
        var edited = previous
        edited.name = "Edited identity profile"
        let saved = try await composition.commit(
            edited, secrets: changed, to: store, previous: previous, installOrder: .beforeDocument,
        )
        #expect(saved.secrets == previous.secrets)
        #expect(secrets.count == 4)
        let reopened = try await ProfileStore(container: root).load(saved.id)
        #expect(reopened == saved)
        let relaunched = ProfileComposition(strategy: .identities(secrets))
        let loaded = try await relaunched.load(reopened)
        try expectSameKeys(loaded, reopened, changed, edited)
        #expect(try await store.load(kept.id) == kept)
        let unaffected = try await relaunched.load(kept)
        try expectSameKeys(unaffected, kept, unrelated.secrets, unrelated.profile)
    }

    @Test
    func `iOS retirement stops at the first failed obsolete reference and swallows the error`() async throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secrets = FakeSecrets()
        let composition = ProfileComposition(strategy: .persistentReferences(secrets))
        let store = ProfileStore(container: root)
        let parsed = try fixture()
        let previous = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store)
        #expect(previous.secrets.presharedKeys.count == 1)
        let obsolete = try ([previous.secrets.privateKey] + Array(previous.secrets.presharedKeys.values)).map { reference in
            guard case let .keychain(data) = reference else { throw ConfigurationError.invalidSecretReference }
            return try JSONDecoder().decode(SecretID.self, from: data)
        }
        #expect(Set(obsolete).count >= 2)
        secrets.refuseAllDeletions()
        // Every obsolete key refuses deletion, so any first attempt must stop retirement, regardless of order.
        let saved = try await composition.commit(parsed.profile, secrets: parsed.secrets, to: store, previous: previous)
        #expect(secrets.deletionAttempts.count == 1)
        #expect(Set(secrets.deletionAttempts).isSubset(of: Set(obsolete)))
        #expect(Set([saved.secrets.privateKey] + Array(saved.secrets.presharedKeys.values))
            .isDisjoint(with: [previous.secrets.privateKey] + Array(previous.secrets.presharedKeys.values)))
        #expect(secrets.count == 4)
        #expect(try await store.load(saved.id) == saved)
        let loaded = try await composition.load(saved)
        try expectSameKeys(loaded, saved, parsed.secrets, parsed.profile)
        let old = try await composition.load(previous)
        try expectSameKeys(old, previous, parsed.secrets, parsed.profile)
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("wgex-lifecycle-\(UUID().uuidString)")
    }

    private func fixture() throws -> ParsedConfiguration {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var bytes = try Array(Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/conf/single-peer-full-tunnel.conf")))
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var parsed = try parseWgQuick(&bytes, name: "Lifecycle")
        parsed.profile.protection.ipv6Policy = .blockOutside
        return parsed
    }

    private func expectSameKeys(
        _ actual: borrowing ParsedSecrets, _ saved: TunnelProfile, _ expected: borrowing ParsedSecrets, _ source: TunnelProfile,
    ) throws {
        let pairs = [(saved.secrets.privateKey, source.secrets.privateKey)] + source.secrets.presharedKeys.map {
            (saved.secrets.presharedKeys[$0.key] ?? $0.value, $0.value)
        }
        for (stored, original) in pairs {
            let equal = try actual.withKey(stored) { left in
                try expected.withKey(original) { left.elementsEqual($0) }
            }
            #expect(equal)
        }
    }
}
