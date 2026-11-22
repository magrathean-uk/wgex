// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// Recording operations and fake services; these tests never connect a real client.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacReverificationTests {
        @Test func `launch consumes the login flag once and coalesces the matching activation`() async {
            var calls: [Bool] = []
            let lifecycle = MacAppActivationCoordinator(isActive: { true }, activation: { calls.append($0) })
            #expect(lifecycle.didBecomeActive() == nil)
            let first = lifecycle.didFinishLaunching(isLoginLaunch: true)
            await first.value
            #expect(lifecycle.didBecomeActive() == nil)
            await lifecycle.didFinishLaunching(isLoginLaunch: false).value
            #expect(calls == [true])
            lifecycle.didResignActive()
            await lifecycle.didBecomeActive()?.value
            #expect(calls == [true, false])
        }

        @Test(arguments: [false, true])
        func `failed deletion requires no generation and no blocking failure`(blocked: Bool) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            var removed = 0
            let status = TunnelStatus(
                phase: .failed(.timedOut, blockedByPolicy: blocked, needsSecrets: false),
                protection: blocked ? .blocked : .unprotected,
                transport: nil,
                health: .idle,
                recentEvents: [],
            )
            let access = MacProfileDaemonAccess(
                permitted: true,
                prepare: { _ in },
                install: { _ in },
                remove: { _, _ in removed += 1 },
                status: { status },
            )
            let repository = MacProfileRepository(
                container: root,
                store: store,
                secrets: InMemorySecretStore(),
                removeProfile: access.remove,
                checkDeletion: access.checkRemoval,
            )
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            let shell = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(deleteProfile: { try await repository.delete($0) }),
            ), profiles: [saved], status: status)
            await shell.deleteProfile(saved)
            #expect(removed == (blocked ? 0 : 1))
            #expect(try await store.list().count == (blocked ? 1 : 0))
            if blocked {
                #expect(shell.operationMessage == MacErrorCopy(.deletionBlocked).message)
                await #expect(throws: MacWorkflowError.deletionBlocked) { try await access.checkRemoval(saved.id) }
            }
        }

        @Test func `status refusal reports its reason and cannot create a delayed deletion`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            var phase = TunnelPhase.active(.init(rawValue: 1))
            var removals = 0
            let access = MacProfileDaemonAccess(
                permitted: true,
                prepare: { _ in },
                install: { _ in },
                remove: { _, _ in removals += 1 },
                status: {
                    .init(
                        phase: phase,
                        protection: .unknown,
                        transport: nil,
                        health: .idle,
                        recentEvents: [],
                    )
                },
            )
            let repository = MacProfileRepository(
                container: root,
                store: store,
                secrets: InMemorySecretStore(),
                removeProfile: access.remove,
                checkDeletion: access.checkRemoval,
            )
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            let shell = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(deleteProfile: { try await repository.delete($0) }),
            ), profiles: [saved])
            await shell.deleteProfile(saved)
            #expect(shell.operationMessage == MacErrorCopy(.deletionBlocked).message)
            phase = .idle
            try await repository.reconcile()
            #expect(removals == 0)
            #expect(try await store.load(saved.id).id == saved.id)
            await shell.deleteProfile(saved)
            #expect(removals == 1)
        }

        @Test(arguments: [false, true])
        func `secure install and unclassified permission refusals remain retryable`(secure: Bool) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            var refused = true
            let repository = MacProfileRepository(container: root, store: store, secrets: InMemorySecretStore(), removeProfile: { _, _ in
                if refused {
                    if secure {
                        throw DaemonError.secureInstallRequired
                    }
                    throw TunnelError.permissionDenied
                }
            })
            let parsed = try EditorFixtures.parsed()
            let saved = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            await #expect(throws: (any Error).self) { try await repository.delete(saved) }
            let path = root.appendingPathComponent("mac-profile-transactions.json")
            let journal = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
            #expect((journal["deleting"] as? [Any])?.count == 1)
            #expect((journal["failedDeletions"] as? [Any])?.isEmpty == true)
            refused = false
            try await repository.reconcile()
            #expect(try await store.list().isEmpty)
        }

        @Test(arguments: [false, true])
        func `failed activation refreshes the list and treats blocking replay as an explicit refusal`(blocked: Bool) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let repository = MacProfileRepository(container: root, store: store, secrets: InMemorySecretStore(), removeProfile: { _, _ in
                throw TunnelError.timedOut
            })
            let first = try EditorFixtures.parsed()
            let saved = try await repository.save(first.profile, secrets: first.secrets, previous: nil)
            await #expect(throws: TunnelError.timedOut) { try await repository.delete(saved) }
            let second = try EditorFixtures.parsed()
            let retained = try await repository.save(second.profile, secrets: second.secrets, previous: nil)
            let app = MacAppModel(
                arguments: ["-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { FakeServiceController(initial: .enabled) },
                applyDockPolicy: { _ in },
            )
            await app.start()
            app.stopObserving()
            app.shell.profiles = []
            app.shell.receive(
                .init(
                    phase: .failed(.timedOut, blockedByPolicy: blocked, needsSecrets: false),
                    protection: blocked ? .blocked : .unprotected,
                    transport: nil,
                    health: .idle,
                    recentEvents: [],
                ),
                at: Date(),
            )
            await app.applicationActivated()
            #expect(app.shell.profiles.contains { $0.id == retained.id })
            #expect(app.shell.profiles.contains { $0.id == saved.id } == blocked)
            if blocked {
                #expect(app.shell.operationMessage == MacErrorCopy(.deletionBlocked).message)
                app.shell.receive(.idle, at: Date())
                await app.applicationActivated()
                #expect(try await store.load(saved.id).id == saved.id)
            }
        }

        @Test(arguments: [DaemonError.downgradeDetected, .secureInstallRequired])
        func `daemon copy is captured before flattening`(error: DaemonError) async throws {
            do {
                let _: Void = try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { throw error }
                Issue.record("Expected refusal")
            } catch {
                let failure = try #require(error as? MacDaemonOperationFailure)
                #expect(MacAppErrorCopy.resolve(failure) == MacAppErrorCopy.resolve(failure.original))
                #expect(failure.copy != MacErrorCopy(.service))
            }
        }

        @Test func `duplicate identities merge without trapping`() {
            let first = TunnelProfile(name: "First")
            var latest = first
            latest.name = "Latest"
            let result = MacAppModel.mergeProfiles(loaded: [first, latest], baseline: [first, first], current: [first])
            #expect(result == [latest])
        }
    }
#endif
