// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore

    @MainActor
    private struct MacProfileConflictTests {
        @Test(arguments: [TunnelError.revisionConflict, .busy])
        func `save rollback never reinstalls a profile after revision conflict`(_ failure: TunnelError) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let secrets = InMemorySecretStore()
            let parsed = try EditorFixtures.parsed()
            let initial = MacProfileRepository(container: root, store: store, secrets: secrets)
            let previous = try await initial.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            var installedNames: [String] = []
            let repository = MacProfileRepository(container: root, store: store, secrets: secrets, installProfile: {
                installedNames.append($0.name)
                throw failure
            })
            var edited = parsed.profile
            edited.name = "Stale edit"
            await #expect(throws: failure) { try await repository.save(edited, secrets: parsed.secrets, previous: previous) }
            #expect(installedNames == (failure == .revisionConflict ? [edited.name] : [edited.name, previous.name]))
            #expect(try await store.load(previous.id) == previous)
        }
    }
#endif
