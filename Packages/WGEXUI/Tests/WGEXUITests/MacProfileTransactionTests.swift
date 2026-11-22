// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacProfileTransactionTests {
        @Test(arguments: [false, true], [IPv6Policy.blockOutside, .allowOutside])
        func `both import actions persist the reviewed IPv6 policy`(_ connect: Bool, _ policy: IPv6Policy) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let persistence = MacPersistence(container: root, simulated: true)
            let secrets = InMemorySecretStore()
            let backend = FakeTunnelBackend()
            let service = FakeServiceController(initial: .enabled)
            let shell = MacShellModel(
                dependencies: MacShellDependencies(backend: backend, service: service, simulated: true),
                status: .idle,
            )
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets)
            let app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository, fakeService: service,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            let parsed = try EditorFixtures.parsed("single-peer-full-tunnel")
            let review = ImportReviewModel(parsed: consume parsed)
            review.ipv6Policy = policy
            var task: Task<Void, Never>?
            #expect(review.confirm { profile, secrets in
                task = try app.confirmImport(profile, secrets: secrets, connect: connect, replacing: nil)
            })
            await task?.value
            let saved = try await app.profileStore.load(review.profile.id)
            #expect(saved.protection.ipv6Policy == policy)
            #expect(saved.validate().allSatisfy { $0.severity != .error })
            #expect(backend.calls.contains(.start(saved.id, transport: nil)) == connect)
        }

        @Test func `blank profile is saved and selected`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            app.openNewProfile()
            let editor = try #require(app.editor)
            #expect(editor.draft.name.isEmpty)
            #expect(!editor.needsPrivateKey, "Create Empty Tunnel generates the key pair (M07-T04)")
            await #expect(throws: (any Error).self) { try await editor.save(using: app.saveEditor) }
            #expect(app.shell.profiles.isEmpty)
            // DEC-088: a name and the key are enough.
            editor.draft.name = "Blank"
            try await editor.save(using: app.saveEditor)
            let blank = try #require(app.shell.profiles.first)
            #expect(app.shell.selectedProfileID == blank.id)
            #expect(try await app.profileStore.load(blank.id) == blank)
            #expect(app.editor == nil)
            app.openNewProfile()
            let complete = try #require(app.editor)
            let parsed = try EditorFixtures.parsed("ipv6-dual-stack")
            complete.draft = ProfileEditorDraft(parsed.profile)
            try await complete.save(using: app.saveEditor)
            let saved = try #require(app.shell.profiles.last)
            #expect(saved.isComplete)
            #expect(app.shell.selectedProfileID == saved.id)
            #expect(try await app.profileStore.load(saved.id) == saved)
        }

        @Test func `editing reuses references and removed PSKs are retired`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let secrets = InMemorySecretStore()
            let repository = MacProfileRepository(container: root, store: store, secrets: secrets)
            let parsed = try EditorFixtures.parsed("multi-peer-split")
            let original = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            let editor = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
            editor.draft.name = "Edited"
            let packed = try editor.makeSecrets()
            let saved = try await repository.save(editor.validatedProfile(), secrets: packed, previous: original)
            #expect(saved.secrets == original.secrets)
            let peer = try #require(editor.draft.peers.first)
            editor.removePresharedKey(peerID: peer.id)
            let removed = try editor.makeSecrets()
            let updated = try await repository.save(editor.validatedProfile(), secrets: removed, previous: saved)
            #expect(updated.secrets.presharedKeys.isEmpty)
            for reference in saved.secrets.presharedKeys.values {
                guard case let .daemonStore(id) = reference else { Issue.record("Expected stored PSK reference"); return }
                #expect(try await !secrets.exists(SecretID(profileID: saved.id, kind: .presharedKey, id: id)))
            }
        }

        @Test func `delete orders daemon purge before secret retirement and file removal`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let secrets = InMemorySecretStore()
            var removals = 0
            var fail = true
            let repository = MacProfileRepository(container: root, store: store, secrets: secrets, removeProfile: { id, purge in
                #expect(purge)
                #expect(try await store.load(id).id == id)
                removals += 1
                if fail {
                    throw TunnelError.backendUnavailable
                }
            })
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            await #expect(throws: TunnelError.backendUnavailable) { try await repository.delete(saved) }
            #expect(try await store.load(saved.id) == saved)
            fail = false
            try await repository.delete(saved)
            #expect(removals == 2)
            #expect(try await store.list().isEmpty)
            guard case let .daemonStore(id) = saved.secrets.privateKey else { Issue.record("Expected stored key reference"); return }
            #expect(try await !secrets.exists(SecretID(profileID: saved.id, kind: .privateKey, id: id)))
        }

        @Test func `interrupted deletion replays from the journal without exposing keys`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let secrets = InMemorySecretStore()
            let first = MacProfileRepository(container: root, store: store, secrets: secrets, removeProfile: { _, _ in
                throw TunnelError.timedOut
            })
            let parsed = try EditorFixtures.parsed()
            let saved = try await first.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            await #expect(throws: TunnelError.timedOut) { try await first.delete(saved) }
            let resumed = MacProfileRepository(container: root, store: store, secrets: secrets, removeProfile: { id, purge in
                #expect(purge)
                throw TunnelError.profileNotFound(id)
            })
            try await resumed.reconcile()
            #expect(try await store.list().isEmpty)
            let journal = try String(contentsOf: root.appendingPathComponent("mac-profile-transactions.json"), encoding: .utf8)
            #expect(try !EditorFixtures.containsSecret(journal))
        }

        @Test func `permanent removal denials leave the automatic retry queue`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            var calls = 0
            let repository = MacProfileRepository(container: root, store: store, secrets: InMemorySecretStore(), removeProfile: { _, _ in
                calls += 1
                throw DaemonError.notAuthorised(.notOwner)
            })
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            await #expect(throws: DaemonError.notAuthorised(.notOwner)) { try await repository.delete(saved) }
            try await repository.reconcile()
            #expect(calls == 1)
            #expect(try await store.load(saved.id) == saved)
            let bytes = try Data(contentsOf: root.appendingPathComponent("mac-profile-transactions.json"))
            let journal = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            #expect((journal["deleting"] as? [Any])?.isEmpty == true)
            #expect((journal["failedDeletions"] as? [Any])?.count == 1)
        }

        @Test func `failed save restores the previous key and profile`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let secrets = InMemorySecretStore()
            let repository = MacProfileRepository(container: root, store: store, secrets: secrets)
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            guard case let .daemonStore(id) = saved.secrets.privateKey else { Issue.record("Expected stored key"); return }
            let account = SecretID(profileID: saved.id, kind: .privateKey, id: id)
            let before = try await secrets.load(account)
            let editor = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
            let alternative = try EditorFixtures.parsed("server-two-peers")
            var replacement = try SecretBytes(zeroedCount: 44)
            try alternative.secrets.withKey(alternative.profile.secrets.privateKey) { raw in
                try replacement.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) }
            }
            try editor.setPrivateKey(replacement)
            let packed = try editor.makeSecrets()
            let failing = MacProfileRepository(container: root, store: ProfileStore(container: root, writeHook: { _, _ in
                throw ProfileStoreError.system(5)
            }), secrets: secrets)
            await #expect(throws: ProfileStoreError.system(5)) {
                try await failing.save(editor.validatedProfile(), secrets: packed, previous: saved)
            }
            let after = try await secrets.load(account)
            let unchanged = before.constantTimeEquals(after)
            #expect(unchanged)
            #expect(try await store.load(saved.id) == saved)
        }

        @Test func `app removes replayed deletions from its visible profile list`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let repository = MacProfileRepository(container: root, store: store, secrets: InMemorySecretStore(), removeProfile: { _, _ in
                throw TunnelError.timedOut
            })
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            await #expect(throws: TunnelError.timedOut) { try await repository.delete(saved) }
            let app = MacAppModel(
                arguments: ["-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { WGEXTesting.FakeServiceController(initial: .enabled) },
                applyDockPolicy: { _ in },
            )
            await app.start()
            await app.applicationActivated()
            defer { app.stopObserving() }
            #expect(app.shell.profiles.isEmpty)
            #expect(try await app.profileStore.list().isEmpty)
        }

        @Test func `one unreadable import never removes other reviews`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root)
            let good = EditorFixtures.root.appendingPathComponent("conf/ipv6-dual-stack.conf")
            app.importURLs([good, root.appendingPathComponent("missing.conf"), good])
            #expect(app.importReviews.count == 2)
            #expect(app.importing)
            #expect(app.shell.operationMessage != nil)
        }
    }
#endif
