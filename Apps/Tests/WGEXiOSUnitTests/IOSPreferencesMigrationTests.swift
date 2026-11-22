// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
// The fake backend links only into Debug and Lab builds; Release never imports WGEXTesting.
#if DEBUG || WGEX_LAB_BUILD
    import Foundation
    import Synchronization
    import Testing
    @testable import WGEX
    import WGEXCore
    import WGEXNEClient
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// On-demand is saved per tunnel; turning it off on the running tunnel keeps the tunnel up (M06-T06).
    @MainActor @Suite(.serialized)
    private struct IOSOnDemandApplyTests {
        @Test
        func `turning on-demand off for the running tunnel saves it and does not stop the tunnel`() async throws {
            let (model, fake, runner) = try await TunnelListSupport.rig(["Home", "Office"])
            // This test disables an existing policy; new tunnels now start with on-demand off.
            for var profile in model.profiles {
                profile.onDemand = .always(exceptSSIDs: [])
                try await model.store.save(profile)
                model.replaceProfile(profile)
            }
            let home = model.profiles[0].id, office = model.profiles[1].id
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) && model.status.protection == .protected }
            let profile = try #require(model.profiles.first { $0.id == home })
            #expect(profile.onDemand == .always(exceptSSIDs: []))
            await model.openEditor(profile)
            let editor = try #require(model.editor)
            #expect(editor.iosOnDemand == IOSOnDemandForm(cellular: true, wifi: true))
            editor.iosOnDemand.cellular = false
            editor.iosOnDemand.wifi = false
            let packed = try editor.makeSecrets()
            try model.saveEditor(editor.validatedProfile(), secrets: packed)
            try await TunnelListSupport.until { model.editor == nil && !model.isBusy }
            #expect(model.profiles.first { $0.id == home }?.onDemand == .off)
            #expect(model.profiles.first { $0.id == office }?.onDemand == .always(exceptSSIDs: []))
            #expect(model.isTunnelOn(home))
            #expect(!fake.calls.contains(.stop(home)))
            #expect(fake.calls.contains(.install(home)))
            #expect(try await ProfileStore(container: model.container).list().first { $0.id == home }?.onDemand == .off)
            // App-wide preferences no longer carry an on-demand policy.
            await model.savePreferences()
            let object = try JSONSerialization.jsonObject(with: Data(contentsOf: model.container.appendingPathComponent("ios-shell.json")))
            #expect(try #require(object as? [String: Any])["onDemand"] == nil)
            await TunnelListSupport.finish(model, runner)
        }
    }

    /// On-demand edits through the real client and persistent Keychain references (M06-T06): the manager's on-demand flag
    /// follows the saved options, and an on-demand-only edit keeps the key items, so the running tunnel is left alone.
    @MainActor @Suite(.serialized, .timeLimit(.minutes(1)))
    private struct IOSOnDemandActivationTests {
        @Test
        func `saving on-demand options arms and disarms the manager and never touches the keys or the running tunnel`() async throws {
            let container = FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-activation-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: container) }
            let system = RecordingManagerSystem(), keychain = ReferenceKeychain()
            let client = NEManagerClient(system: system, platform: .iOS)
            let model = AppModel(composition: IOSAppComposition(container: container, keychain: keychain, backend: client))
            let runner = Task { await model.run() }
            try await TunnelListSupport.until { !model.statusHistory.isEmpty }
            model.prepareFixture()
            await model.confirmImport()
            let imported = try #require(model.profiles.first)
            let manager = try #require(await system.record(for: imported.id))
            #expect(!manager.isOnDemandEnabled)

            // Enabled options on a disarmed manager arm it; nothing is started.
            await model.openEditor(imported)
            var editor = try #require(model.editor)
            editor.iosOnDemand = IOSOnDemandForm(cellular: false, wifi: true)
            try await save(editor, in: model)
            #expect(model.operationMessage == nil)
            #expect(model.profiles.first?.onDemand != imported.onDemand)
            #expect(await system.record(for: imported.id)?.isOnDemandEnabled == true)
            #expect(await !system.calls.contains("start"))

            // The tunnel runs; on-demand off then saves and disarms without a reload, stop or start.
            await model.setTunnel(imported.id, on: true)
            await system.emit(manager.id, .connected)
            try await TunnelListSupport.until { model.isTunnelOn(imported.id) && Self.isActive(model.status.phase) }
            let running = try #require(model.profiles.first)
            let revision = await system.record(for: imported.id)?.profileRevision
            let items = keychain.references, mark = await system.calls.count
            await model.openEditor(running)
            editor = try #require(model.editor)
            editor.iosOnDemand = IOSOnDemandForm()
            try await save(editor, in: model)
            let saved = try #require(model.profiles.first)
            #expect(model.operationMessage == nil)
            #expect(saved.onDemand == .off)
            #expect(saved.secrets == running.secrets)
            #expect(keychain.references == items)
            let record = try #require(await system.record(for: imported.id))
            #expect(!record.isOnDemandEnabled)
            #expect(record.profileRevision == revision)
            let after = await system.calls.dropFirst(mark)
            #expect(!after.contains("start") && !after.contains("stop") && !after.contains("message"))
            #expect(model.isTunnelOn(imported.id))
            #expect(try await ProfileStore(container: container).load(imported.id).secrets == running.secrets)
            runner.cancel()
            await runner.value
            await client.shutdown()
        }

        @Test(arguments: [false, true])
        func `changed keys saved with on-demand options survive reopening through the save callback`(privateKey: Bool) async throws {
            let rig = try await rig()
            defer { rig.runner.cancel() }
            let model = rig.model
            model.prepareFixture()
            await model.confirmImport()
            let imported = try #require(model.profiles.first)
            await model.openEditor(imported)
            var editor = try #require(model.editor)
            let peer = try #require(editor.draft.peers.first?.id)
            let initialKey = try encodedKey(7)
            try editor.setPresharedKey(initialKey, peerID: peer)
            try await save(editor, in: model)

            try await model.openEditor(#require(model.profiles.first))
            editor = try #require(model.editor)
            let editedPeer = try #require(editor.draft.peers.first?.id)
            if privateKey {
                editor.generateKeypair()
            } else {
                let replacement = try encodedKey(8)
                try editor.setPresharedKey(replacement, peerID: editedPeer)
            }
            editor.iosOnDemand = IOSOnDemandForm(cellular: false, wifi: true)
            let submitted = try editor.validatedProfile()
            let reference = privateKey ? submitted.secrets.privateKey : try #require(submitted.secrets.presharedKeys.values.first)
            let packed = try editor.makeSecrets()
            var expected = try SecretBytes(zeroedCount: 32)
            try packed.withKey(reference) { key in expected.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            try model.saveEditor(submitted, secrets: packed)
            try await TunnelListSupport.until { model.editor == nil && !model.isBusy }
            #expect(model.operationMessage == nil)

            // Reload the document and Keychain values, rather than the submitted editor's buffers.
            let stored = try await model.store.load(imported.id)
            await model.openEditor(stored)
            let reopened = try #require(model.editor).makeSecrets()
            let savedReference = privateKey ? stored.secrets.privateKey : try #require(stored.secrets.presharedKeys.values.first)
            var actual = try SecretBytes(zeroedCount: 32)
            try reopened.withKey(savedReference) { key in actual.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            let changedKeyWasSaved = expected.constantTimeEquals(actual)
            #expect(changedKeyWasSaved)
            #expect(stored.onDemand == submitted.onDemand)
            await rig.finish()
        }

        @Test(arguments: [false, true], [false, true])
        func `the first save callback arms exactly the new tunnels with on-demand rules`(cellular: Bool, wifi: Bool) async throws {
            let options = IOSOnDemandForm(cellular: cellular, wifi: wifi)
            let rig = try await rig()
            defer { rig.runner.cancel() }
            rig.model.createFromScratch()
            let editor = try #require(rig.model.editor)
            try configureScratch(editor)
            editor.iosOnDemand = options
            try await save(editor, in: rig.model)
            #expect(rig.model.operationMessage == nil)
            let profile = try #require(rig.model.profiles.first)
            let manager = try #require(await rig.system.record(for: profile.id))
            #expect(manager.isOnDemandEnabled == options.isEnabled)
            #expect(await !rig.system.calls.contains("start"))
            await rig.finish()
        }

        @Test(arguments: [false, true])
        func `a failed activation is persisted and an unchanged save callback retries it`(arming: Bool) async throws {
            let rig = try await rig()
            defer { rig.runner.cancel() }
            let id = try await prepareActivation(in: rig, arming: arming)
            #expect(rig.model.operationMessage == AppModel.onDemandFailedMessage)
            #expect(try pendingIDs(rig.model) == [id])
            #expect(rig.model.pendingOnDemandActivation == [id])
            #expect(await rig.system.record(for: id)?.isOnDemandEnabled == !arming)
            let references = rig.keychain.references
            let revision = await rig.system.record(for: id)?.profileRevision
            let mark = await rig.system.calls.count
            let attempts = await rig.system.activationAttempts

            await rig.system.failActivation(false)
            try await rig.model.openEditor(#require(rig.model.profiles.first))
            try await save(#require(rig.model.editor), in: rig.model)
            #expect(rig.model.operationMessage == nil)
            #expect(await rig.system.record(for: id)?.isOnDemandEnabled == arming)
            #expect(try pendingIDs(rig.model).isEmpty)
            #expect(rig.model.pendingOnDemandActivation.isEmpty)
            #expect(rig.keychain.references == references)
            #expect(await rig.system.record(for: id)?.profileRevision == revision)
            let after = await rig.system.calls.dropFirst(mark)
            #expect(!after.contains("start") && !after.contains("stop") && !after.contains("message"))
            #expect(await rig.system.activationAttempts > attempts)
            await rig.finish()
        }

        @Test(arguments: [false, true])
        func `launch retries pending activation and retains it across another failure`(arming: Bool) async throws {
            let rig = try await rig()
            defer { rig.runner.cancel() }
            let id = try await prepareActivation(in: rig, arming: arming)
            let container = rig.model.container
            let records = await rig.system.loadAll()
            rig.runner.cancel()
            await rig.runner.value
            await rig.client.shutdown()

            let failing = try await self.rig(container: container, keychain: rig.keychain, records: records, failing: true)
            defer { failing.runner.cancel() }
            #expect(failing.model.operationMessage == AppModel.onDemandFailedMessage)
            #expect(try pendingIDs(failing.model) == [id])
            #expect(failing.model.pendingOnDemandActivation == [id])
            #expect(await failing.system.activationAttempts > 0)
            failing.runner.cancel()
            await failing.runner.value
            await failing.client.shutdown()

            let retry = try await self.rig(container: container, keychain: rig.keychain, records: failing.system.loadAll())
            defer { retry.runner.cancel() }
            #expect(retry.model.operationMessage == nil)
            #expect(await retry.system.record(for: id)?.isOnDemandEnabled == arming)
            #expect(try pendingIDs(retry.model).isEmpty)
            #expect(retry.model.pendingOnDemandActivation.isEmpty)
            #expect(await retry.system.activationAttempts == 1)
            await retry.finish()
        }

        @Test
        func `an unchanged save and launch keep a user-disabled manager off`() async throws {
            let rig = try await rig()
            defer { rig.runner.cancel() }
            rig.model.createFromScratch()
            let editor = try #require(rig.model.editor)
            try configureScratch(editor)
            editor.iosOnDemand = IOSOnDemandForm(wifi: true)
            try await save(editor, in: rig.model)
            let id = try #require(rig.model.profiles.first?.id)
            await rig.model.setTunnel(id, on: false)
            let mark = await rig.system.activationAttempts
            try await rig.model.openEditor(#require(rig.model.profiles.first))
            let unchanged = try #require(rig.model.editor)
            unchanged.draft.name = "Renamed"
            try await save(unchanged, in: rig.model)
            #expect(await rig.system.record(for: id)?.isOnDemandEnabled == false)
            #expect(await rig.system.activationAttempts == mark)
            #expect(try pendingIDs(rig.model).isEmpty)
            rig.runner.cancel()
            await rig.runner.value
            await rig.client.shutdown()
            let again = try await self.rig(
                container: rig.model.container, keychain: rig.keychain, records: rig.system.loadAll(),
            )
            defer { again.runner.cancel() }
            #expect(await again.system.record(for: id)?.isOnDemandEnabled == false)
            #expect(await again.system.activationAttempts == 0)
            await again.finish()
        }
    }

    private extension IOSOnDemandActivationTests {
        @MainActor private struct Rig {
            let model: AppModel
            let system: RecordingManagerSystem
            let keychain: ReferenceKeychain
            let client: NEManagerClient
            let runner: Task<Void, Never>

            func finish() async {
                runner.cancel()
                await runner.value
                await client.shutdown()
                try? FileManager.default.removeItem(at: model.container)
            }
        }

        private func rig(
            container: URL? = nil, keychain: ReferenceKeychain = ReferenceKeychain(),
            records: [VPNManagerRecord] = [], failing: Bool = false,
        ) async throws -> Rig {
            let container = container ?? FileManager.default.temporaryDirectory
                .appendingPathComponent("WGEX-activation-\(UUID().uuidString)")
            let system = RecordingManagerSystem(records: records)
            await system.failActivation(failing)
            let client = NEManagerClient(system: system, platform: .iOS)
            let model = AppModel(composition: IOSAppComposition(container: container, keychain: keychain, backend: client))
            let runner = Task { await model.run() }
            try await TunnelListSupport.until { !model.statusHistory.isEmpty }
            return Rig(model: model, system: system, keychain: keychain, client: client, runner: runner)
        }

        private func configureScratch(_ editor: ProfileEditorModel) throws {
            editor.draft.addresses = "192.0.2.2/32"
            editor.addPeer()
            editor.draft.peers[0].publicKey = try PrivateKey.generate().publicKey().base64
            editor.draft.peers[0].endpoint = "vpn.example.invalid:51820"
            editor.allTraffic(peerID: editor.draft.peers[0].id)
            editor.draft.protection.ipv6Policy = .blockOutside
        }

        private func encodedKey(_ value: UInt8) throws -> SecretBytes {
            var encoded = try SecretBytes(zeroedCount: 44)
            try [UInt8](repeating: value, count: 32).withUnsafeBytes { raw in
                try encoded.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) }
            }
            return encoded
        }

        /// Deliberately uses the production form callback, including its snapshot and unstructured commit task.
        private func save(_ editor: ProfileEditorModel, in model: AppModel) async throws {
            let packed = try editor.makeSecrets()
            try model.saveEditor(editor.validatedProfile(), secrets: packed)
            try await TunnelListSupport.until { model.editor == nil && !model.isBusy }
        }

        private func pendingIDs(_ model: AppModel) throws -> Set<UUID> {
            let data = try Data(contentsOf: model.container.appendingPathComponent("ios-shell.json"))
            let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
            return Set((object["onDemandActivation"] as? [String] ?? []).compactMap(UUID.init(uuidString:)))
        }

        private func prepareActivation(in rig: Rig, arming: Bool) async throws -> UUID {
            rig.model.prepareFixture()
            await rig.model.confirmImport()
            let id = try #require(rig.model.profiles.first?.id)
            if !arming {
                try await rig.model.openEditor(#require(rig.model.profiles.first))
                let editor = try #require(rig.model.editor)
                editor.iosOnDemand = IOSOnDemandForm(wifi: true)
                try await save(editor, in: rig.model)
            }
            await rig.system.failActivation(true)
            try await rig.model.openEditor(#require(rig.model.profiles.first))
            let editor = try #require(rig.model.editor)
            editor.iosOnDemand = arming ? IOSOnDemandForm(cellular: true) : IOSOnDemandForm()
            try await save(editor, in: rig.model)
            return id
        }

        private static func isActive(_ phase: TunnelPhase) -> Bool {
            if case .active = phase {
                return true
            }
            return false
        }
    }

    /// The system's VPN managers in memory: records every call, answers no provider message, emits statuses on request.
    private actor RecordingManagerSystem: VPNManagerSystem {
        private var stored: [VPNManagerRecord] = []
        private(set) var calls: [String] = []
        private var sequence: UInt64 = 0
        private var activationFails = false
        private(set) var activationAttempts = 0
        private let events: AsyncStream<VPNStatusEvent>
        private let continuation: AsyncStream<VPNStatusEvent>.Continuation

        init(records: [VPNManagerRecord] = []) {
            stored = records
            (events, continuation) = AsyncStream.makeStream()
        }

        func failActivation(_ fails: Bool) {
            activationFails = fails
        }

        func record(for profileID: UUID) -> VPNManagerRecord? {
            stored.first { $0.configuration.profileID == profileID }
        }

        func emit(_ manager: UUID, _ status: VPNStatus) {
            sequence += 1
            if let index = stored.firstIndex(where: { $0.id == manager }) {
                stored[index].status = status
            }
            continuation.yield(VPNStatusEvent(managerID: manager, sequence: sequence, status: status))
        }

        func loadAll() -> [VPNManagerRecord] {
            calls.append("load"); return stored
        }

        func save(_ record: VPNManagerRecord) throws {
            calls.append("save")
            let previous = stored.first { $0.id == record.id }
            if record.isOnDemandEnabled != (previous?.isOnDemandEnabled ?? false) {
                activationAttempts += 1
                if activationFails {
                    throw TunnelError.backendUnavailable
                }
            }
            var record = record
            if let old = stored.first(where: { $0.id == record.id }) {
                record.status = old.status
            }
            stored.removeAll { $0.id == record.id }; stored.append(record)
        }

        func remove(_ id: UUID) {
            calls.append("remove"); stored.removeAll { $0.id == id }
        }

        func start(_: UUID, transport _: UUID?) {
            calls.append("start")
        }

        func stop(_: UUID) {
            calls.append("stop")
        }

        func startConfirmed(_: UUID, revision _: String?) {
            calls.append("start")
        }

        func statusEvents() -> AsyncStream<VPNStatusEvent> {
            events
        }

        func sendProviderMessage(_: UUID, data _: Data) throws -> Data {
            calls.append("message")
            throw TunnelError.backendUnavailable
        }
    }

    /// Keychain stand-in with persistent references: every stored item gets a reference of its own, as the Keychain does.
    /// Test keys are throwaway; nothing reaches the host or simulator Keychain.
    private final class ReferenceKeychain: PersistentReferenceSecretStore, @unchecked Sendable {
        private let items = Mutex<[SecretID: [UInt8]]>([:])

        /// Every stored item's persistent reference.
        var references: Set<Data> {
            items.withLock { Set($0.keys.map(Self.reference)) }
        }

        private static func reference(_ id: SecretID) -> Data {
            Data("ref:\(id.profileID.uuidString):\(id.kind.rawValue):\(id.id.uuidString)".utf8)
        }

        private func id(_ reference: Data) -> SecretID? {
            items.withLock { $0.keys.first { Self.reference($0) == reference } }
        }

        func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
            let bytes = secret.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> [UInt8] in Array(raw) }
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
            guard items.withLock({ $0.removeValue(forKey: id) }) != nil else { throw .notFound }
        }

        func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
            let bytes = secret.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> [UInt8] in Array(raw) }
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
            guard let id = id(persistentReference) else { throw .notFound }
            return try await load(id)
        }

        func delete(persistentReference: Data) async throws(SecretStoreError) {
            guard let id = id(persistentReference) else { throw .notFound }
            try await delete(id)
        }
    }
#endif
