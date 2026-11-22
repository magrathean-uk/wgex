// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
@testable import WGEX
import WGEXCore
import WGEXNEClient
import WGEXProfileStore
import WGEXUI

/// An in-memory stand-in for the Keychain. Nothing here reaches the host or simulator Keychain; test keys are throwaway.
private final class FakeKeychain: PersistentReferenceSecretStore, @unchecked Sendable {
    private let items = Mutex<[SecretID: [UInt8]]>([:])
    private let failStores = Mutex(false)
    private let failDeletes = Mutex(false)

    var count: Int {
        items.withLock { $0.count }
    }

    var accounts: Set<String> {
        items.withLock { Set($0.keys.map(\.account)) }
    }

    func failFurtherStores() {
        failStores.withLock { $0 = true }
    }

    /// While set, every delete throws `.locked` and removes nothing; clear it to let a retry through.
    func failDeletes(_ fail: Bool) {
        failDeletes.withLock { $0 = fail }
    }

    func contains(_ reference: Data) -> Bool {
        guard let id = Self.id(reference) else { return false }
        return items.withLock { $0[id] != nil }
    }

    private static func bytes(of secret: borrowing SecretBytes) -> [UInt8] {
        secret.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> [UInt8] in Array(raw) }
    }

    private static func reference(_ id: SecretID) -> Data {
        Data("ref:\(id.profileID.uuidString):\(id.kind.rawValue):\(id.id.uuidString)".utf8)
    }

    private static func id(_ reference: Data) -> SecretID? {
        let parts = String(decoding: reference, as: UTF8.self).split(separator: ":").map(String.init)
        guard parts.count == 4, parts[0] == "ref", let profile = UUID(uuidString: parts[1]),
              let kind = SecretID.Kind(rawValue: parts[2]), let id = UUID(uuidString: parts[3]) else { return nil }
        return SecretID(profileID: profile, kind: kind, id: id)
    }

    func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
        guard !failStores.withLock({ $0 }) else { throw .locked }
        let bytes = Self.bytes(of: secret)
        try items.withLock { items throws(SecretStoreError) in
            guard items[id] == nil else { throw .duplicate }
            items[id] = bytes
        }
    }

    func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
        guard let bytes = items.withLock({ $0[id] }) else { throw .notFound }
        guard var buffer = try? SecretBytes(zeroedCount: bytes.count) else { throw .system(-1) }
        buffer.withUnsafeMutableBytes { destination in
            bytes.withUnsafeBytes { destination.copyMemory(from: $0) }
        }
        return buffer
    }

    func delete(_ id: SecretID) async throws(SecretStoreError) {
        guard !failDeletes.withLock({ $0 }) else { throw .locked }
        guard items.withLock({ $0.removeValue(forKey: id) }) != nil else { throw .notFound }
    }

    func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
        let bytes = Self.bytes(of: secret)
        try items.withLock { items throws(SecretStoreError) in
            guard items[id] != nil else { throw .notFound }
            items[id] = bytes
        }
    }

    func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
        items.withLock { $0[id] != nil }
    }

    func persistentReference(for id: SecretID) async throws(SecretStoreError) -> Data {
        guard items.withLock({ $0[id] != nil }) else { throw .notFound }
        return Self.reference(id)
    }

    func load(persistentReference: Data) async throws(SecretStoreError) -> SecretBytes {
        guard let id = Self.id(persistentReference) else { throw .notFound }
        return try await load(id)
    }

    func delete(persistentReference: Data) async throws(SecretStoreError) {
        guard let id = Self.id(persistentReference) else { throw .notFound }
        try await delete(id)
    }
}

/// Records calls; optionally refuses installs or removals.
private final class RecordingBackend: TunnelBackend, @unchecked Sendable {
    let capabilities: BackendCapabilities = []
    private let state = Mutex((installed: [TunnelProfile](), removed: [UUID](), purged: [Bool]()))
    private let installError = Mutex<TunnelError?>(nil)
    private let removeError = Mutex<TunnelError?>(nil)
    private let stopError = Mutex<TunnelError?>(nil)
    private let stopped = Mutex([UUID]())

    var installed: [TunnelProfile] {
        state.withLock { $0.installed }
    }

    var removed: [UUID] {
        state.withLock { $0.removed }
    }

    var purged: [Bool] {
        state.withLock { $0.purged }
    }

    func failInstalls(with error: TunnelError) {
        installError.withLock { $0 = error }
    }

    var stops: [UUID] {
        stopped.withLock { $0 }
    }

    func failRemovals(with error: TunnelError) {
        removeError.withLock { $0 = error }
    }

    func failStops(with error: TunnelError) {
        stopError.withLock { $0 = error }
    }

    func install(_ profile: TunnelProfile) async throws(TunnelError) {
        if let error = installError.withLock({ $0 }) {
            throw error
        }
        state.withLock { $0.installed.append(profile) }
    }

    func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
        if let error = removeError.withLock({ $0 }) {
            throw error
        }
        state.withLock { $0.removed.append(id); $0.purged.append(purgeSecrets) }
    }

    func start(_: UUID, transport _: TransportID?) async throws(TunnelError) {}
    func stop(_ id: UUID) async throws(TunnelError) {
        stopped.withLock { $0.append(id) }
        if let error = stopError.withLock({ $0 }) {
            throw error
        }
    }

    func statusUpdates() -> AsyncStream<TunnelStatus> {
        AsyncStream { $0.yield(.idle) }
    }

    func statistics() async throws(TunnelError) -> TunnelStatistics {
        throw .backendUnavailable
    }
}

private struct WaitTimedOut: Error {}

@MainActor
private struct WGEXiOSKeychainBridgeTests {
    private func container() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-bridge-\(UUID().uuidString)", isDirectory: true)
    }

    private func model(
        _ root: URL, _ keychain: FakeKeychain, backend: RecordingBackend? = nil, simulator: Bool = false,
    ) -> AppModel {
        AppModel(composition: IOSAppComposition(container: root, keychain: keychain, backend: backend, simulator: simulator))
    }

    /// Bounded poll; a stuck condition fails the test instead of hanging the suite.
    private func waitUntil(timeout: Duration = .seconds(5), _ condition: () -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while !condition() {
            guard clock.now < deadline else { throw WaitTimedOut() }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    /// A fresh model over the same container, as after a relaunch. run() is cancelled once the profiles are loaded.
    private func relaunch(_ root: URL, _ keychain: FakeKeychain, backend: RecordingBackend? = nil) async throws -> AppModel {
        let relaunched = model(root, keychain, backend: backend)
        let task = Task { await relaunched.run() }
        defer { task.cancel() }
        try await waitUntil { !relaunched.profiles.isEmpty }
        return relaunched
    }

    private func importFixture(_ model: AppModel) async throws -> TunnelProfile {
        model.prepareFixture()
        await model.confirmImport()
        return try #require(model.profiles.first)
    }

    private func keychainReferences(_ profile: TunnelProfile) -> [Data] {
        ([profile.secrets.privateKey] + Array(profile.secrets.presharedKeys.values)).compactMap {
            if case let .keychain(reference) = $0 {
                reference
            } else {
                nil
            }
        }
    }

    @Test
    func `import stores keys in the keychain and persists keychain references`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let model = model(root, keychain, backend: backend)
        let profile = try await importFixture(model)
        #expect(model.operationMessage == nil)
        guard case .keychain = profile.secrets.privateKey else {
            Issue.record("private key reference is not a keychain reference")
            return
        }
        #expect(keychain.count == 1 + profile.secrets.presharedKeys.count)
        let references = keychainReferences(profile)
        #expect(references.count == keychain.count)
        #expect(references.allSatisfy { keychain.contains($0) })
        let onDisk = try await model.store.load(profile.id)
        #expect(onDisk.secrets == profile.secrets)
        #expect(backend.installed.map(\.secrets) == [profile.secrets])
    }

    @Test
    func `editor opens from the keychain after a relaunch`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let first = model(root, keychain)
        _ = try await importFixture(first)
        let relaunched = try await relaunch(root, keychain)
        let profile = try #require(relaunched.profiles.first)
        await relaunched.openEditor(profile)
        #expect(relaunched.operationMessage == nil)
        let editor = try #require(relaunched.editor)
        #expect(!editor.needsPrivateKey)
        #expect(editor.publicKey == profile.interface.publicKey)
    }

    @Test
    func `editor save seals fresh items and retires the superseded ones`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let original = try await importFixture(first)
        let relaunched = try await relaunch(root, keychain, backend: backend)
        await relaunched.openEditor(original)
        let editor = try #require(relaunched.editor)
        editor.draft.name = "Renamed"
        try await editor.save { profile, secrets in try relaunched.saveEditor(profile, secrets: secrets) }
        try await waitUntil { relaunched.editor == nil && !relaunched.isBusy }
        #expect(relaunched.operationMessage == nil)
        let saved = try #require(relaunched.profiles.first)
        #expect(saved.name == "Renamed")
        let oldReferences = keychainReferences(original)
        let newReferences = keychainReferences(saved)
        #expect(newReferences.count == oldReferences.count)
        #expect(Set(newReferences).isDisjoint(with: oldReferences))
        #expect(keychain.count == newReferences.count)
        #expect(newReferences.allSatisfy { keychain.contains($0) })
        #expect(try await relaunched.store.load(saved.id).secrets == saved.secrets)
        #expect(backend.installed.last?.secrets == saved.secrets)
    }

    @Test
    func `delete after a relaunch removes every keychain item`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let profile = try await importFixture(first)
        #expect(keychain.count > 0)
        let relaunched = try await relaunch(root, keychain, backend: backend)
        await relaunched.deleteProfiles(at: IndexSet(integer: 0))
        #expect(relaunched.operationMessage == nil)
        #expect(relaunched.profiles.isEmpty)
        #expect(keychain.count == 0)
        #expect(try await relaunched.store.list().isEmpty)
        #expect(backend.removed == [profile.id])
        #expect(backend.purged == [true])
    }

    @Test
    func `a failed install rolls back the keys and the stored profile`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        backend.failInstalls(with: .backendUnavailable)
        let model = model(root, keychain, backend: backend)
        model.prepareFixture()
        await model.confirmImport()
        #expect(model.profiles.isEmpty)
        #expect(model.operationMessage != nil)
        #expect(keychain.count == 0)
        #expect(try await model.store.list().isEmpty)
    }

    @Test
    func `a refused keychain write saves nothing`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        keychain.failFurtherStores()
        let model = model(root, keychain)
        model.prepareFixture()
        await model.confirmImport()
        #expect(model.profiles.isEmpty)
        #expect(model.operationMessage != nil)
        #expect(try await model.store.list().isEmpty)
    }

    @Test
    func `simulator without a fake request composes the real path with a clear unavailable state`() async {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let model = AppModel(arguments: [], simulator: true, environment: [:], container: root)
        #expect(!model.usesFakeBackend)
        #expect(model.backend == nil)
        #expect(model.secrets is KeychainSecretStore)
        #expect(model.status.protection == .unknown)
        #expect(model.operationMessage == "VPN unavailable on the simulator.")
        #expect(model.backendMessage == "VPN unavailable on the simulator.")
        await model.toggleConnection()
        #expect(model.operationMessage == "VPN unavailable on the simulator.")
    }

    @Test
    func `simulator keeps the fake only when asked`() {
        let flag = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        let hosted = AppModel(arguments: [], simulator: true, environment: ["WGEX_HOSTED_TESTS": "1"])
        let plain = AppModel(arguments: [], simulator: true, environment: [:])
        #expect(flag.usesFakeBackend && flag.backend != nil)
        #expect(hosted.usesFakeBackend && hosted.backend != nil)
        #expect(!plain.usesFakeBackend && plain.backend == nil)
    }

    @Test
    func `device without a launch flag composes the NE client and the keychain`() {
        // Runs in the simulator test host only; the NetworkExtensionManagerSystem init is inert (no Network Extension call is made).
        let model = AppModel(arguments: [], simulator: false, environment: [:])
        #expect(model.backend is NEManagerClient)
        #expect(model.secrets is KeychainSecretStore)
        #expect(!model.usesFakeBackend)
        #expect(model.status.protection == .unknown)
        #expect(model.operationMessage == nil)
    }

    /// Real `KeychainSecretStore` in the WGEX-owned simulator's own Keychain (never the host login keychain). Opt in with
    /// `TEST_RUNNER_WGEX_HOSTED_TESTS=1`. It proves the Keychain bridge only; Network Extension does not run on the simulator,
    /// so nothing here says anything about a real tunnel.
    @Test(.enabled(if: Self.hostedKeychainEnabled, "Set TEST_RUNNER_WGEX_HOSTED_TESTS=1; simulator Keychain only."))
    func `hosted simulator Keychain round trip through the bridge`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = KeychainSecretStore()
        let first = AppModel(composition: IOSAppComposition(container: root, keychain: keychain, backend: nil, simulator: true))
        let profile = try await importFixture(first)
        let references = keychainReferences(profile)
        do {
            #expect(!references.isEmpty)
            for reference in references {
                let key = try await keychain.load(persistentReference: reference)
                #expect(key.count == 32)
            }
            let relaunched = AppModel(composition: IOSAppComposition(container: root, keychain: keychain, backend: nil, simulator: true))
            let task = Task { await relaunched.run() }
            defer { task.cancel() }
            try await waitUntil { !relaunched.profiles.isEmpty }
            await relaunched.openEditor(profile)
            #expect(relaunched.editor != nil)
            await relaunched.deleteProfiles(at: IndexSet(integer: 0))
            #expect(relaunched.profiles.isEmpty)
            for reference in references {
                await #expect(throws: SecretStoreError.notFound) { _ = try await keychain.load(persistentReference: reference) }
            }
        } catch {
            await purge(references, from: keychain)
            throw error
        }
        await purge(references, from: keychain)
    }

    /// Awaited cleanup so no item outlives the test, on success or on a thrown failure.
    private func purge(_ references: [Data], from keychain: KeychainSecretStore) async {
        for reference in references {
            try? await keychain.delete(persistentReference: reference)
        }
    }

    private nonisolated static var hostedKeychainEnabled: Bool {
        #if targetEnvironment(simulator)
            ProcessInfo.processInfo.environment["WGEX_HOSTED_TESTS"] == "1"
        #else
            false
        #endif
    }
}

/// Delete paths, split out of the suite body to keep it within the lint length limit; same file, so the fakes stay private.
private extension WGEXiOSKeychainBridgeTests {
    @Test
    func `delete proceeds when the backend never installed the profile`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let profile = try await importFixture(first)
        backend.failRemovals(with: .profileNotFound(profile.id))
        await first.deleteProfiles(at: IndexSet(integer: 0))
        #expect(first.operationMessage == nil)
        #expect(first.profiles.isEmpty)
        #expect(keychain.count == 0)
        #expect(try await first.store.list().isEmpty)
    }

    @Test
    func `delete of the selected profile proceeds when the VPN configuration is already gone`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let profile = try await importFixture(first)
        #expect(first.selectedProfileID == profile.id)
        // The user removed the WGEX VPN configuration in iOS Settings: stop and remove both find no manager.
        backend.failStops(with: .profileNotFound(profile.id))
        backend.failRemovals(with: .profileNotFound(profile.id))
        await first.deleteProfiles(at: IndexSet(integer: 0))
        #expect(backend.stops == [profile.id])
        #expect(first.operationMessage == nil)
        #expect(first.profiles.isEmpty)
        #expect(keychain.count == 0)
        #expect(try await first.store.list().isEmpty)
    }

    @Test
    func `a stop failure other than a missing configuration still blocks the delete`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let profile = try await importFixture(first)
        let stored = keychain.count
        backend.failStops(with: .backendUnavailable)
        await first.deleteProfiles(at: IndexSet(integer: 0))
        #expect(first.operationMessage == "The profile could not be deleted. Try again.")
        #expect(first.profiles.map(\.id) == [profile.id])
        #expect(keychain.count == stored)
        #expect(try await first.store.list().map(\.id) == [profile.id])
    }

    @Test
    func `a keychain delete failure leaves the profile deletable and orphans no items`() async throws {
        let root = container()
        defer { try? FileManager.default.removeItem(at: root) }
        let keychain = FakeKeychain()
        let backend = RecordingBackend()
        let first = model(root, keychain, backend: backend)
        let profile = try await importFixture(first)
        let stored = keychain.count
        #expect(stored > 0)
        keychain.failDeletes(true)
        await first.deleteProfiles(at: IndexSet(integer: 0))
        #expect(first.operationMessage == "The profile could not be deleted. Try again.")
        // The document is kept while any item might remain, so the retry still knows every reference.
        #expect(first.profiles.map(\.id) == [profile.id])
        #expect(keychain.count == stored)
        #expect(try await first.store.list().map(\.id) == [profile.id])
        keychain.failDeletes(false)
        await first.deleteProfiles(at: IndexSet(integer: 0))
        #expect(first.profiles.isEmpty)
        #expect(keychain.count == 0)
        #expect(try await first.store.list().isEmpty)
    }
}
