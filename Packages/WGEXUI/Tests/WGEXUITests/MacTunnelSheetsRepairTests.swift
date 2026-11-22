// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M07-T04 repair round (REV-M07-T04 and adversarial pass 1): Add All retry, stale import lines, deletes while busy.
    @MainActor
    @Suite("M07-T04 tunnel sheets repair", .timeLimit(.minutes(1)))
    private struct MacTunnelSheetsRepairTests {
        @MainActor
        private final class DeleteLog {
            var ids: [UUID] = []
        }

        private let quickWait = MacIdleWait(attempts: 3) {}

        /// Review 3, A5 and A8: after one save fails, a second Add All retries only that tunnel; the saved ones are neither
        /// renamed, re-saved nor listed twice.
        @Test func `Add All retries only the tunnels that failed`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let persistence = MacPersistence(container: root, simulated: true)
            let secrets = InMemorySecretStore()
            let service = FakeServiceController(initial: .enabled)
            let shell = MacShellModel(
                dependencies: MacShellDependencies(backend: FakeTunnelBackend(), service: service, simulated: true), status: .idle,
            )
            let failing = DeleteLog()
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets, installProfile: { profile in
                if failing.ids.contains(profile.id) {
                    failing.ids.removeAll { $0 == profile.id }
                    throw TunnelError.backendUnavailable
                }
            })
            let app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository, fakeService: service,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            var reviews: [ImportReviewModel] = []
            for (name, fixture) in [("Alpha", "ipv6-dual-stack"), ("Bravo", "multi-peer-split"), ("Charlie", "single-peer-full-tunnel")] {
                var bytes = try EditorFixtures.bytes(fixture)
                let parsed = try parseWgQuick(&bytes, name: name)
                reviews.append(ImportReviewModel(parsed: consume parsed))
            }
            failing.ids = [reviews[1].profile.id]
            app.importReviews = reviews
            app.importing = true
            await app.confirmAllImports()?.value
            #expect(app.shell.profiles.map(\.name) == ["Alpha", "Charlie"])
            #expect(app.importReviews.map(\.name) == ["Bravo"], "Only the failed review stays for a retry")
            #expect(app.importing)
            #expect(app.importErrorMessage != nil)
            let first = try await app.profileStore.list()
            await app.confirmAllImports()?.value
            #expect(app.shell.profiles.map(\.name) == ["Alpha", "Charlie", "Bravo"])
            #expect(Set(app.shell.profiles.map(\.id)).count == 3)
            #expect(app.importReviews.isEmpty && !app.importing && app.importErrorMessage == nil)
            let after = try await app.profileStore.list()
            #expect(after.count == 3)
            for saved in first {
                #expect(after.first { $0.id == saved.id } == saved, "\(saved.name) was not saved again")
            }
            // Backstop: a review whose tunnel is already listed is never staged again.
            app.importReviews = [reviews[0]]
            #expect(app.confirmAllImports() == nil)
        }

        /// A6: a line about an earlier source never shows under a later, good import.
        @Test func `stale import lines are cleared by Cancel and by a new import`() throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            app.importErrorMessage = MacStrings.clipboardHoldsNoConfiguration
            app.cancelImport()
            #expect(app.importErrorMessage == nil)
            app.importErrorMessage = MacStrings.clipboardHoldsNoConfiguration
            app.importURLs([EditorFixtures.root.appendingPathComponent("conf/ipv6-dual-stack.conf")])
            #expect(app.importErrorMessage == nil)
            #expect(app.importReviews.count == 1)
            let imports = try source("Apps/WGEXMac/MacAppModel+Import.swift")
            let choose = try #require(imports.components(separatedBy: "func chooseImportFile() {").last)
                .components(separatedBy: "NSOpenPanel()")[0]
            #expect(choose.contains("importReviews = []; importErrorMessage = nil"))
        }

        /// A7: Delete pressed while an Activate is still in flight says why nothing happened.
        @Test func `a delete while another command runs says why`() async throws {
            let backend = FakeTunnelBackend()
            backend.scriptStart([
                .init(phase: .preparing(Generation(rawValue: 1)), protection: .blocked, delay: .milliseconds(400)),
                .init(phase: .active(Generation(rawValue: 1)), protection: .protected),
            ])
            let deleted = DeleteLog()
            let profile = TunnelProfile(name: "Home")
            let shell = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: FakeServiceController(initial: .enabled), simulated: true,
                operations: MacShellOperations(deleteProfile: { deleted.ids.append($0.id) }),
            ), profiles: [profile, TunnelProfile(name: "Cabin")], status: .idle)
            shell.selectedProfileID = profile.id
            let starting = Task { await shell.toggleConnection() }
            for _ in 0 ..< 10000 where !shell.busy {
                await Task.yield()
            }
            try #require(shell.busy)
            let busyCopy = MacErrorCopy(error: MacWorkflowError.operationInProgress).message
            await shell.deleteProfile(profile, idleWait: quickWait)
            #expect(shell.operationMessage == MacStrings.tunnelNotDeletedNotDeactivated("Home", reason: busyCopy))
            let other = try #require(shell.profiles.last)
            await shell.deleteProfile(other, idleWait: quickWait)
            #expect(shell.operationMessage == busyCopy)
            #expect(deleted.ids.isEmpty)
            await starting.value
        }

        private func source(_ path: String) throws -> String {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            return try String(contentsOf: root.appending(path: path), encoding: .utf8)
        }
    }
#endif
