// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacMergeCompositionTests {
        @Test func `preview composition never evaluates real factories and shares its transaction store`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            var realCalls = 0
            var guardCalls = 0
            let service = FakeServiceController()
            let app = MacAppModel(
                arguments: ["-WGEXFakeBackend"], container: root,
                fakeServiceFactory: { service },
                realServiceFactory: { realCalls += 1; return FakeServiceController() },
                systemOperationsPermitted: { guardCalls += 1; return false },
                applyDockPolicy: { _ in },
            )
            #expect(app.shell.simulated)
            #expect(!app.shell.hostGuarded)
            #expect(app.secretStore is InMemorySecretStore)
            let parsed = try EditorFixtures.parsed()
            let saved = try await app.repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            #expect(try await app.profileStore.load(saved.id).id == saved.id)
            app.simulateApproval()
            await app.shell.refreshService()
            #expect(app.shell.serviceState == .enabled)
            #expect(realCalls == 0)
            #expect(guardCalls == 0)
        }

        @Test func `guarded real composition retains workflow injection without selecting preview storage`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            var fakeCalls = 0
            var realCalls = 0
            let app = MacAppModel(
                arguments: [], container: root,
                fakeServiceFactory: { fakeCalls += 1; return FakeServiceController() },
                realServiceFactory: { realCalls += 1; return FakeServiceController() },
                systemOperationsPermitted: { false }, applyDockPolicy: { _ in },
            )
            #expect(!app.shell.simulated)
            #expect(app.shell.hostGuarded)
            #if WGEX_LAB_BUILD
                // Lab builds compose the guarded file store for the real backend (P1-11): ad hoc signing has
                // no Keychain access group and the lab automation must never meet a Keychain ACL prompt.
                #expect(app.secretStore is LabFileSecretStore)
                #expect(!(app.secretStore is KeychainSecretStore))
            #else
                #expect(app.secretStore is KeychainSecretStore)
            #endif
            #expect(!(app.secretStore is InMemorySecretStore))
            #expect(fakeCalls == 0)
            #expect(realCalls == 1)
        }
    }
#endif
