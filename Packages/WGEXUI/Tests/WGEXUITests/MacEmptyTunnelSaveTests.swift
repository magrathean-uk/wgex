// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// A-EMPTY (DEC-088, M04-T15-EDITOR): Create Empty Tunnel saves with a name and a key alone; a missing address or server
    /// blocks activation, never saving, and the tunnel never reaches the daemon until it is complete.
    @MainActor
    @Suite("M07-T04 empty tunnel save", .timeLimit(.minutes(1)))
    private struct MacEmptyTunnelSaveTests {
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

        @Test func `a named empty tunnel saves, reloads and is never installed`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            #expect(!editor.needsPrivateKey, "Create Empty Tunnel pre-generates the key pair")
            #expect(editor.draft.name.isEmpty)
            #expect(!editor.canSave, "An empty name still blocks Save")
            #expect(editor.diagnostics.contains { $0.diagnostic.code == .limitExceeded })
            editor.draft.name = "Empty"
            #expect(editor.canSave)
            #expect(!editor.diagnostics.contains { $0.diagnostic.code == .limitExceeded })
            let warnings = editor.diagnostics.map(\.diagnostic).filter { $0.severity == .warning }.map(\.message)
            #expect(warnings.contains(MacStrings.addAnAddressBeforeActivating))
            #expect(warnings.contains(MacStrings.addAServerBeforeActivating))
            try await editor.save(using: rig.app.saveEditor)
            let saved = try #require(rig.app.shell.profiles.first)
            #expect(saved.name == "Empty")
            #expect(!saved.isComplete)
            #expect(rig.app.editor == nil)
            #expect(rig.installs.ids.isEmpty, "An incomplete tunnel is never installed in the daemon")
            #expect(rig.backend.calls.isEmpty)
            // A fresh store with the Mac's opt-in loads it; the default store still quarantines it.
            let reloaded = try await MacPersistence(container: rig.root, simulated: true).store.list()
            #expect(reloaded.map(\.id) == [saved.id])
            let strict = ProfileStore(container: rig.root)
            #expect(try await strict.list().isEmpty)
            #expect(await strict.takeQuarantinedProfiles() == [saved.id])
        }

        /// M07-T14: the lab row's own steps (Generate Key Pair, a name, an address, no server) must store the tunnel.
        @Test func `an empty tunnel with a regenerated key and an address is stored`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            let first = editor.publicKey
            editor.generateKeypair()
            #expect(editor.publicKey != first)
            editor.draft.name = "wgex-lab-m07-empty-a1"
            editor.draft.addresses = "10.250.0.2/32"
            #expect(editor.canSave, "problems: \(editor.diagnostics.map(\.diagnostic.message))")
            try await editor.save(using: rig.app.saveEditor)
            let saved = try #require(rig.app.shell.profiles.first)
            #expect(saved.name == "wgex-lab-m07-empty-a1")
            #expect(rig.app.shell.selectedProfileID == saved.id)
            let stored = try await MacPersistence(container: rig.root, simulated: true).store.list()
            #expect(stored.map(\.id) == [saved.id])
            #expect(stored.first?.interface.addresses.count == 1)
            let keys = try await rig.app.storedSecrets(saved)
            let storedPublicKey = try keys.withKey(saved.secrets.privateKey) {
                try PrivateKey(bytes: SecretBytes(copying: $0)).publicKey()
            }
            #expect(storedPublicKey == editor.publicKey)
        }

        @Test func `the page, the menu and the login start refuse to activate it`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            editor.draft.name = "Empty"
            try await editor.save(using: rig.app.saveEditor)
            let shell = rig.app.shell
            let saved = try #require(shell.selectedProfile)
            #expect(shell.activationBlocker == MacStrings.activationNeedsAddressAndServer)
            #expect(!shell.canConnect)
            await shell.toggleConnection()
            await shell.toggleMenuTunnel(saved.id)
            #expect(shell.operationMessage == MacStrings.activationNeedsAddressAndServer)
            #expect(rig.backend.calls.isEmpty)
            var options = saved
            options.macOptions.autoConnectAtLogin = true
            shell.profiles = [options]
            await shell.connectAtLogin()
            #expect(rig.backend.calls.isEmpty)
            // Deactivate, Cancel and Check Again are not blocked.
            shell.receive(TunnelStatus(
                phase: .active(Generation(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: [],
            ), at: Date())
            #expect(shell.canConnect)
        }

        @Test func `an incomplete tunnel refuses start-up and on-demand choices`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            editor.draft.name = "Empty"
            editor.draft.macOptions.autoConnectAtLogin = true
            #expect(!editor.canSave)
            #expect(editor.diagnostics.contains { $0.diagnostic.message == MacStrings.incompleteTunnelOptions })
            editor.draft.macOptions.autoConnectAtLogin = false
            try await editor.save(using: rig.app.saveEditor)
            await rig.app.shell.saveStartup(.login)
            #expect(rig.app.shell.operationMessage == MacStrings.incompleteTunnelOptions)
            #expect(rig.app.shell.selectedProfile?.macOptions == MacProfileOptions())
        }

        @Test func `completing it installs it, and a complete tunnel cannot be saved back to incomplete`() async throws {
            let rig = rig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            rig.app.openNewProfile()
            let editor = try #require(rig.app.editor)
            editor.draft.name = "Empty"
            try await editor.save(using: rig.app.saveEditor)
            let saved = try #require(rig.app.shell.profiles.first)
            let savedSecrets = try await rig.app.storedSecrets(saved)
            let complete = try ProfileEditorModel(profile: saved, secrets: savedSecrets, allowsIncomplete: true)
            complete.draft.addresses = "10.8.0.2/32"
            complete.addPeer()
            let peer = try #require(complete.draft.peers.first)
            complete.draft.peers[0].publicKey = try EditorFixtures.profile().peers[0].publicKey.base64
            complete.draft.peers[0].endpoint = "203.0.113.7:51820"
            complete.draft.peers[0].allowedIPs = AllowedIPsModel(["10.8.0.0/24"])
            #expect(complete.draft.peers[0].id == peer.id)
            #expect(complete.canSave)
            try await complete.save(using: rig.app.saveEditor)
            let completed = try #require(rig.app.shell.profiles.first)
            #expect(completed.isComplete)
            #expect(rig.installs.ids == [completed.id])
            #expect(rig.app.shell.activationBlocker == nil)
            // The editor of a complete tunnel keeps missing address and server as errors ...
            let completedSecrets = try await rig.app.storedSecrets(completed)
            let again = try ProfileEditorModel(profile: completed, secrets: completedSecrets, allowsIncomplete: true)
            again.draft.addresses = ""
            #expect(!again.canSave)
            #expect(again.diagnostics.contains { $0.diagnostic.code == .noAddresses && $0.diagnostic.severity == .error })
            // ... and the repository refuses the downgrade outright.
            var stripped = completed
            stripped.interface.addresses = []
            await #expect(throws: ProfileStoreError.invalidDocument) {
                try await rig.app.repository.save(stripped, secrets: rig.app.storedSecrets(completed), previous: completed)
            }
        }

        @Test func `iPhone and TV editors keep the full gate`() {
            let editor = ProfileEditorModel()
            editor.generateKeypair()
            editor.draft.name = "Phone"
            #expect(!editor.canSave)
            #expect(editor.diagnostics.contains { $0.diagnostic.code == .noAddresses && $0.diagnostic.severity == .error })
            #expect(editor.diagnostics.contains { $0.diagnostic.code == .noPeers && $0.diagnostic.severity == .error })
        }
    }
#endif
