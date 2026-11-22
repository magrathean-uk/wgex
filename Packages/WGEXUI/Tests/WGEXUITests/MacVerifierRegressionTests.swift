// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// Recording operations, fake services and guarded composition construction; no real client is connected.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacVerifierRegressionTests {
        @Test func `guarded profile operations and import never call the client`() async throws {
            var clientCalls = 0
            let access = MacProfileDaemonAccess(
                permitted: false, prepare: { _ in clientCalls += 1 },
                install: { _ in clientCalls += 1 }, remove: { _, _ in clientCalls += 1 },
            )
            access.isReady = { true }
            let parsed = try EditorFixtures.parsed()
            await #expect(throws: ServiceError.hostGuard) { try await access.install(parsed.profile) }
            await #expect(throws: ServiceError.hostGuard) { try await access.remove(parsed.profile.id, true) }
            #expect(clientCalls == 0)
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(
                container: root,
                realServiceFactory: { FakeServiceController() },
                systemOperationsPermitted: { false },
                applyDockPolicy: { _ in },
            )
            #expect(throws: ServiceError.hostGuard) {
                try app.confirmImport(parsed.profile, secrets: parsed.secrets, connect: false, replacing: nil)
            }
            #expect(try await app.profileStore.list().isEmpty)
        }

        @Test func `import succeeds locally without a daemon`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            let parsed = try EditorFixtures.parsed()
            let task = try app.confirmImport(parsed.profile, secrets: parsed.secrets, connect: false, replacing: nil)
            await task.value
            #expect(app.shell.profiles.count == 1)
            #expect(try await app.profileStore.list().count == 1)
            #expect(!app.shell.daemonRunning)
        }

        @Test func `optional daemon install requires readiness and cannot roll back a local save`() async throws {
            var calls = 0
            let access = MacProfileDaemonAccess(permitted: true, prepare: { _ in }, install: { _ in
                calls += 1
                throw TunnelError.backendUnavailable
            }, remove: { _, _ in })
            let parsed = try EditorFixtures.parsed()
            try await access.install(parsed.profile)
            #expect(calls == 0)
            access.isReady = { true }
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let repository = MacProfileRepository(container: root, store: store, secrets: InMemorySecretStore(), installProfile: {
                #expect(try await store.load($0.id).id == $0.id)
                try await access.install($0)
            })
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            #expect(calls == 1)
            #expect(try await store.load(saved.id) == saved)
        }

        @Test func `future nested preferences and corrupt settings preserve onboarding`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let data = Data(#"{"onboardingComplete":true,"hideDockIcon":true,"global":{"lockdown":"future"},"flags":{"future":true}}"#.utf8)
            let decoded = try JSONDecoder().decode(MacPreferences.self, from: data)
            #expect(decoded.onboardingComplete)
            #expect(decoded.global == .defaults)
            #expect(decoded.flags == .defaults)
            try data.write(to: root.appendingPathComponent("mac-preferences.json"))
            try Data("invalid settings".utf8).write(to: root.appendingPathComponent("settings.json"))
            let loaded = try await MacPersistence(container: root, simulated: true).load()
            #expect(loaded.onboardingComplete)
            #expect(loaded.hideDockIcon)
        }

        @Test func `non idle status refuses deletion of any profile when identity is uncertain`() async {
            var calls = 0
            let first = TunnelProfile(name: "Selected")
            let other = TunnelProfile(name: "Possibly active")
            let shell = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(deleteProfile: { _ in calls += 1 }),
            ), profiles: [first, other], status: .init(
                phase: .active(.init(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: [],
            ))
            await shell.deleteProfile(other)
            #expect(calls == 0)
            #expect(shell.profiles.count == 2)
        }

        @Test func `activation merge retains concurrent saves and deletions`() {
            let first = TunnelProfile(name: "Original")
            let deleted = TunnelProfile(name: "Deleted")
            let inserted = TunnelProfile(name: "Imported")
            var edited = first
            edited.name = "Edited"
            let result = MacAppModel.mergeProfiles(loaded: [first, deleted], baseline: [first, deleted], current: [edited, inserted])
            #expect(result == [edited, inserted])
        }

        @Test func `stop permits a new observation lifetime and preferences load`() async {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            var loads = 0
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, preferencesLoader: {
                loads += 1
                return MacPreferences()
            }, applyDockPolicy: { _ in })
            await app.start()
            app.stopObserving()
            await app.start()
            defer { app.stopObserving() }
            #expect(loads == 2)
            #expect(app.uiWork != nil)
        }

        @Test func `missing bundled example has explicit copy and quarantine stays outside import`() async {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            await app.loadFixture(name: "Example")
            #expect(app.shell.operationMessage == MacErrorCopy(.fixtureUnavailable).message)
            app.shell.reportQuarantinedProfiles()
            app.openImport()
            #expect(app.importErrorMessage == nil)
        }

        @Test func `a busy repository reports an operation in progress`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let (entered, signal) = AsyncStream<Void>.makeStream()
            let (release, unblock) = AsyncStream<Void>.makeStream()
            let repository = MacProfileRepository(
                container: root,
                store: ProfileStore(container: root),
                secrets: InMemorySecretStore(),
                installProfile: { _ in
                    signal.yield(())
                    for await _ in release {
                        break
                    }
                },
            )
            let save = Task {
                let parsed = try EditorFixtures.parsed()
                return try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            }
            var arrivals = entered.makeAsyncIterator()
            await arrivals.next()
            await #expect(throws: MacWorkflowError.operationInProgress) { try await repository.delete(TunnelProfile(name: "Busy")) }
            unblock.yield(())
            _ = try await save.value
            signal.finish(); unblock.finish()
        }

        @Test(arguments: [false, true]) func `unchanged startup policy permits local rename offline or active`(active: Bool) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            let parsed = try EditorFixtures.parsed()
            var bootProfile = parsed.profile
            bootProfile.macOptions.startBeforeLogin = true
            let saved = try await app.repository.save(bootProfile, secrets: parsed.secrets, previous: nil)
            app.shell.profiles = [saved]
            app.shell.selectedProfileID = saved.id
            if active {
                app.shell.receive(
                    .init(phase: .active(.init(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: []),
                    at: Date(),
                )
            }
            guard case let .daemonStore(id) = saved.secrets.privateKey else { Issue.record("Expected local reference"); return }
            let key = try await app.secretStore.load(SecretID(profileID: saved.id, kind: .privateKey, id: id))
            let secrets = try ParsedSecrets(bytes: key, references: [saved.secrets.privateKey: 0 ..< 32])
            var renamed = saved
            renamed.name = "Renamed offline"
            try await app.saveEditor(renamed, secrets: secrets)
            #expect(try await app.profileStore.load(saved.id).name == renamed.name)
            if active {
                // M05-T05: the startup option of the profile that is itself active saves, as the official app edits it.
                var changed = renamed
                changed.macOptions = MacProfileOptions()
                try await app.saveEditor(changed, secrets: secrets)
                #expect(try await app.profileStore.load(saved.id).macOptions == MacProfileOptions())
            }
        }

        @Test func `hidden Dock login launch performs the full pass without an activation notification`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            var dock: [Bool] = []
            let app = MacAppModel(
                arguments: ["-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { FakeServiceController(initial: .enabled) },
                preferencesLoader: {
                    var preferences = MacPreferences()
                    preferences.hideDockIcon = true
                    return preferences
                },
                applyDockPolicy: { dock.append($0) },
            )
            let parsed = try EditorFixtures.parsed()
            var profile = parsed.profile
            profile.macOptions.autoConnectAtLogin = true
            let saved = try await app.repository.save(profile, secrets: parsed.secrets, previous: nil)
            var calls: [Bool] = []
            let lifecycle = MacAppActivationCoordinator(isActive: { false }, activation: { login in
                calls.append(login)
                await app.start()
                await app.applicationActivated()
                if login {
                    await app.shell.connectAtLogin()
                }
            })
            await lifecycle.didFinishLaunching(isLoginLaunch: true).value
            defer { app.stopObserving() }
            #expect(app.shell.daemonRunning)
            // Launch joins the connection request; the separate status-stream consumer publishes the profile later.
            try await waitForPublishedState { app.shell.activeProfileID == saved.id }
            #expect(app.shell.activeProfileID == saved.id)
            #expect(dock == [true])
            await lifecycle.didBecomeActive()?.value
            #expect(calls == [true, false])
        }

        private func waitForPublishedState(timeout: Duration = .seconds(30), _ condition: () -> Bool) async throws {
            let deadline = ContinuousClock.now + timeout
            while !condition() {
                try #require(ContinuousClock.now < deadline, "Timed out waiting for the required UI state")
                try await Task.sleep(for: .milliseconds(1))
            }
        }

        @Test func `workflow error consequences describe the operation accurately`() {
            #expect(!MacAppErrorCopy.resolve(DaemonError.secureInstallRequired).consequence.contains("Boot"))
            #expect(MacAppErrorCopy.resolve(ProfileStoreError.unsupportedVersion(99)) == MacErrorCopy(.document))
            #expect(MacAppErrorCopy.resolve(ProfileStoreError.invalidDocument) == MacErrorCopy(.store))
            #expect(MacErrorCopy(error: MacWorkflowError.loginItem) == MacErrorCopy(.loginItem))
        }
    }
#endif
