// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// REV-M07-T04 item 4: a failed save of a tunnel removes the daemon registration it created, and a removal the daemon
    /// refuses stays journalled through every later failure until `reconcile` completes it.
    @MainActor
    @Suite("M07-T04 registration rollback", .timeLimit(.minutes(1)))
    private struct MacEmptyTunnelRollbackTests {
        private struct Rig {
            let root: URL
            let app: MacAppModel
            let backend: FakeTunnelBackend
            let installs: InstallLog
        }

        @MainActor
        private final class InstallLog {
            var ids: [UUID] = []
            var removals: [UUID] = []
            /// Removals that throw before one succeeds.
            var failingRemovals = 0
            /// Installations that throw (the daemon registers nothing) before one succeeds.
            var failingInstalls = 0
        }

        private func rig() -> Rig {
            let root = MacWorkflowTests.scratch()
            let persistence = MacPersistence(container: root, simulated: true)
            let secrets = InMemorySecretStore()
            let backend = FakeTunnelBackend()
            let service = FakeServiceController(initial: .enabled)
            let shell = MacShellModel(
                dependencies: MacShellDependencies(backend: backend, service: service, simulated: true),
                status: .idle,
            )
            let installs = InstallLog()
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets, installProfile: {
                if installs.failingInstalls > 0 {
                    installs.failingInstalls -= 1
                    throw TunnelError.backendUnavailable
                }
                installs.ids.append($0.id)
            }, removeProfile: { id, purge in
                #expect(purge)
                installs.removals.append(id)
                if installs.failingRemovals > 0 {
                    installs.failingRemovals -= 1
                    throw TunnelError.backendUnavailable
                }
            })
            let app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository, fakeService: service,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            return Rig(root: root, app: app, backend: backend, installs: installs)
        }

        // MARK: Review item 4: completing an empty tunnel and then failing undoes the new daemon registration

        private func savedEmpty(_ rig: Rig) async throws -> TunnelProfile {
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            editor.draft.name = "Empty"
            try await editor.save(using: rig.app.saveEditor)
            return try #require(rig.app.shell.profiles.first)
        }

        private func completed(_ profile: TunnelProfile) throws -> TunnelProfile {
            var complete = profile
            complete.interface.addresses = try [IPAddressRange("10.8.0.2/32")]
            complete.peers = try [PeerConfiguration(
                publicKey: EditorFixtures.profile().peers[0].publicKey, allowedIPs: [IPAddressRange("10.8.0.0/24")],
            )]
            return complete
        }

        private func journal(_ rig: Rig) throws -> [String] {
            let url = rig.root.appendingPathComponent("mac-profile-transactions.json")
            guard FileManager.default.fileExists(atPath: url.path) else { return [] }
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            return object["unregistering"] as? [String] ?? []
        }

        @Test func `a failed first complete save restores the document and keys and removes the new registration`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            let before = try await rig.app.storedSecrets(saved)
            let complete = try completed(saved)
            await #expect(throws: TunnelError.timedOut) {
                _ = try await rig.app.repository
                    .save(complete, secrets: rig.app.storedSecrets(saved), previous: saved) { _ in throw TunnelError.timedOut }
            }
            #expect(rig.installs.ids == [saved.id], "The save registered the tunnel ...")
            #expect(rig.installs.removals == [saved.id], "... and the rollback removed that registration")
            #expect(try await rig.app.profileStore.load(saved.id) == saved)
            let after = try await rig.app.storedSecrets(saved)
            let same = try before.withKey(saved.secrets.privateKey) { old in
                try after.withKey(saved.secrets.privateKey) { new in old.elementsEqual(new) }
            }
            #expect(same)
            #expect(try journal(rig).isEmpty)
        }

        @Test func `a removal the daemon refuses is journalled, retried and dropped once the tunnel is saved complete`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            let complete = try completed(saved)
            rig.installs.failingRemovals = 1
            await #expect(throws: TunnelError.timedOut) {
                _ = try await rig.app.repository
                    .save(complete, secrets: rig.app.storedSecrets(saved), previous: saved) { _ in throw TunnelError.timedOut }
            }
            #expect(try journal(rig) == [saved.id.uuidString])
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals == [saved.id, saved.id])
            #expect(try journal(rig).isEmpty)
            // A pending removal never undoes a later, successful complete save.
            rig.installs.failingRemovals = 1
            await #expect(throws: TunnelError.timedOut) {
                _ = try await rig.app.repository
                    .save(complete, secrets: rig.app.storedSecrets(saved), previous: saved) { _ in throw TunnelError.timedOut }
            }
            #expect(try journal(rig) == [saved.id.uuidString])
            let installed = try await rig.app.repository.save(complete, secrets: rig.app.storedSecrets(saved), previous: saved)
            #expect(installed.isComplete)
            #expect(try journal(rig).isEmpty)
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals.count == 3, "No removal after the tunnel was saved complete")
        }

        // MARK: Double failures (REV-M07-T04 prior-2): a journalled removal survives every failed retry

        /// A complete save of the empty tunnel whose start-up step fails, so the save is rolled back.
        private func failComplete(_ rig: Rig, _ saved: TunnelProfile, with error: TunnelError) async throws {
            await #expect(throws: error) {
                _ = try await rig.app.repository.save(
                    completed(saved), secrets: rig.app.storedSecrets(saved), previous: saved,
                ) { _ in throw error }
            }
        }

        @Test func `failed removal, then failed installation, then reconcile removes the earlier registration`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            rig.installs.failingRemovals = 1
            try await failComplete(rig, saved, with: .timedOut)
            #expect(try journal(rig) == [saved.id.uuidString])
            rig.installs.failingInstalls = 1
            await #expect(throws: TunnelError.backendUnavailable) {
                _ = try await rig.app.repository.save(completed(saved), secrets: rig.app.storedSecrets(saved), previous: saved)
            }
            #expect(try journal(rig) == [saved.id.uuidString], "A failed retry keeps the pending removal")
            #expect(try await rig.app.profileStore.load(saved.id) == saved)
            #expect(try await rig.app.storedSecrets(saved).references.count == 1)
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals == [saved.id, saved.id])
            #expect(try journal(rig).isEmpty)
        }

        @Test func `failed installation, then failed removal, then reconcile removes the registration`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            rig.installs.failingInstalls = 1
            await #expect(throws: TunnelError.backendUnavailable) {
                _ = try await rig.app.repository.save(completed(saved), secrets: rig.app.storedSecrets(saved), previous: saved)
            }
            #expect(rig.installs.removals.isEmpty, "Nothing was registered, so nothing is removed")
            #expect(try journal(rig).isEmpty)
            rig.installs.failingRemovals = 1
            try await failComplete(rig, saved, with: .timedOut)
            #expect(try journal(rig) == [saved.id.uuidString])
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals == [saved.id, saved.id])
            #expect(try journal(rig).isEmpty)
        }

        @Test func `a removal that fails during reconcile stays journalled for the next one`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            rig.installs.failingRemovals = 2
            try await failComplete(rig, saved, with: .timedOut)
            await #expect(throws: TunnelError.backendUnavailable) { try await rig.app.repository.reconcile() }
            #expect(try journal(rig) == [saved.id.uuidString])
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals == [saved.id, saved.id, saved.id])
            #expect(try journal(rig).isEmpty)
        }

        @Test func `a revision conflict on a retry keeps the earlier pending removal`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            rig.installs.failingRemovals = 1
            try await failComplete(rig, saved, with: .timedOut)
            try await failComplete(rig, saved, with: .revisionConflict)
            #expect(rig.installs.removals == [saved.id], "The conflicting retry touches nothing in the daemon")
            #expect(try journal(rig) == [saved.id.uuidString], "... and keeps the earlier clean-up intent")
            #expect(try await rig.app.profileStore.load(saved.id) == saved)
            try await rig.app.repository.reconcile()
            #expect(rig.installs.removals == [saved.id, saved.id])
            #expect(try journal(rig).isEmpty)
        }

        @Test func `a revision conflict leaves the daemon registration alone`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let saved = try await savedEmpty(rig)
            await #expect(throws: TunnelError.revisionConflict) {
                _ = try await rig.app.repository.save(completed(saved), secrets: rig.app.storedSecrets(saved), previous: saved) { _ in
                    throw TunnelError.revisionConflict
                }
            }
            #expect(rig.installs.removals.isEmpty)
            #expect(try await rig.app.profileStore.load(saved.id) == saved)
        }
    }
#endif
