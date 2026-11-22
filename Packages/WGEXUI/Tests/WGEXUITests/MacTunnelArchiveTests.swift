// SPDX-License-Identifier: MIT

#if os(macOS)
    import Darwin
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    @MainActor
    @Suite("M02-T08 export all tunnels", .timeLimit(.minutes(1)))
    private struct MacTunnelArchiveTests {
        private static let fixtures = [
            ("Zulu", "ipv6-dual-stack"), ("Alpha", "ipv6-dual-stack"), ("Mike", "ipv6-dual-stack"),
        ]

        private struct Harness {
            let root: URL
            let out: URL
            let app: MacAppModel
            /// Normalised wg-quick bytes per tunnel name, taken before the keys moved into the secret store.
            let expected: [String: [UInt8]]
        }

        private func harness(_ entries: [(String, String)] = fixtures) async throws -> Harness {
            let root = MacWorkflowTests.scratch()
            let persistence = MacPersistence(container: root, simulated: true)
            let secrets = InMemorySecretStore()
            let service = FakeServiceController(initial: .enabled)
            let shell = MacShellModel(
                dependencies: MacShellDependencies(backend: FakeTunnelBackend(), service: service, simulated: true),
                status: .idle,
            )
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets)
            let app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository, fakeService: service,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            var profiles: [TunnelProfile] = []
            var expected: [String: [UInt8]] = [:]
            for (name, fixture) in entries {
                var bytes = try EditorFixtures.bytes(fixture)
                let parsed = try parseWgQuick(&bytes, name: name)
                let text = try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
                expected[name] = text.bytes.withUnsafeBytes { Array($0) }
                try await profiles.append(repository.save(parsed.profile, secrets: parsed.secrets, previous: nil))
            }
            shell.profiles = profiles
            // The store creates its own private container; the tests write archives beside it.
            let out = root.appendingPathComponent("out")
            try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
            return Harness(root: root, out: out, app: app, expected: expected)
        }

        private func zeroText(_ count: Int) throws -> SecretText {
            try SecretText(bytes: SecretBytes(zeroedCount: count))
        }

        @Test func `entry names follow the official flat layout and never collide`() {
            let names = MacTunnelArchive.entryNames(for: ["Home", "Home", "", "a/b", "A/B", "Tab\tName", "1"])
            #expect(names == ["Home.conf", "1.conf", "2.conf", "a_b.conf", "3.conf", "Tab_Name.conf", "4.conf"])
            #expect(Set(names.map { $0.lowercased() }).count == names.count)
            #expect(names.allSatisfy { !$0.contains("/") && $0.hasSuffix(".conf") })
        }

        @Test func `archive round trips through the zip import with exact configuration bytes`() async throws {
            let harness = try await harness()
            defer { try? FileManager.default.removeItem(at: harness.root) }
            let destination = harness.out.appendingPathComponent("all")
            #expect(await harness.app.exportAll(to: destination))
            #expect(harness.app.exportAllMessage == nil)
            #expect(!harness.app.exportAllRunning)
            let written = harness.out.appendingPathComponent("all.zip")
            let data = try Data(contentsOf: written)
            let entries = try MacImportSources.archive(data)
            // Sorted by tunnel name, like the official app's list.
            #expect(entries.map(\.0) == ["Alpha", "Mike", "Zulu"])
            for (name, bytes) in entries {
                let original = try #require(harness.expected[name])
                #expect(bytes == original)
                var copy = bytes
                let parsed = try parseWgQuick(&copy, name: name)
                #expect(parsed.profile.name == name)
                #expect(!parsed.diagnostics.contains { $0.severity == .error })
            }
            #expect(data.range(of: Data("$WGEX_SECRET:".utf8)) == nil)
        }

        @Test func `archive file is private from creation and leaves no temporary file`() async throws {
            let harness = try await harness()
            defer { try? FileManager.default.removeItem(at: harness.root) }
            let destination = harness.out.appendingPathComponent("keys.zip")
            #expect(await harness.app.exportAll(to: destination))
            var info = stat()
            #expect(stat(destination.path, &info) == 0)
            #expect(info.st_mode & 0o777 == 0o600)
            let names = try FileManager.default.contentsOfDirectory(atPath: harness.out.path)
            #expect(!names.contains { $0.hasPrefix(".wgex-") })
        }

        @Test func `writer limits keep every archive importable and leave nothing behind`() async throws {
            let root = MacWorkflowTests.scratch()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let destination = root.appendingPathComponent("limit.zip")
            #expect(MacTunnelArchive.maximumEntries == 1024)
            #expect(MacTunnelArchive.maximumBytes == MacTunnelArchive.maximumEntries * MacTunnelArchive.maximumEntryBytes)
            await #expect(throws: MacTunnelArchive.Failure.empty) {
                try await MacTunnelArchive.write(names: [], to: destination) { _ in try self.zeroText(1) }
            }
            let many = (0 ... MacTunnelArchive.maximumEntries).map { "T\($0)" }
            await #expect(throws: MacTunnelArchive.Failure.tooManyTunnels) {
                try await MacTunnelArchive.write(names: many, to: destination) { _ in
                    Issue.record("no configuration may be read once the count is refused")
                    return try self.zeroText(1)
                }
            }
            await #expect(throws: MacTunnelArchive.Failure.tooLarge) {
                try await MacTunnelArchive.write(names: ["Big"], to: destination) { _ in
                    try self.zeroText(MacTunnelArchive.maximumEntryBytes + 1)
                }
            }
            // The total bound, exercised with a small limit instead of 256 MiB of key text.
            await #expect(throws: MacTunnelArchive.Failure.tooLarge) {
                try await MacTunnelArchive.write(names: ["A", "B", "C"], to: destination, byteLimit: 200) { _ in try self.zeroText(60) }
            }
            struct Boom: Error {}
            await #expect(throws: Boom.self) {
                try await MacTunnelArchive.write(names: ["A", "B"], to: destination) { index in
                    if index == 1 {
                        throw Boom()
                    }
                    return try self.zeroText(8)
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
        }

        @Test func `a full archive of 1024 tunnels writes and reads back`() async throws {
            let root = MacWorkflowTests.scratch()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let destination = root.appendingPathComponent("full.zip")
            let names = (0 ..< MacTunnelArchive.maximumEntries).map { "T\($0)" }
            try await MacTunnelArchive.write(names: names, to: destination) { _ in try zeroText(16) }
            let entries = try MacImportSources.archive(Data(contentsOf: destination))
            #expect(entries.map(\.0) == names)
        }

        @Test func `sixty five tunnels round trip through the zip import`() async throws {
            let entries = (0 ..< 65).map { (String(format: "T%02d", $0), "ipv6-dual-stack") }
            let harness = try await harness(entries)
            defer { try? FileManager.default.removeItem(at: harness.root) }
            let destination = harness.out.appendingPathComponent("sixty-five.zip")
            #expect(await harness.app.exportAll(to: destination))
            #expect(harness.app.exportAllMessage == nil)
            let read = try MacImportSources.archive(Data(contentsOf: destination))
            #expect(read.count == 65)
            #expect(read.map(\.0) == entries.map(\.0))
            for (name, bytes) in read {
                #expect(bytes == harness.expected[name])
            }
        }

        @Test func `more than 1024 tunnels fail with fixed copy and write nothing`() async throws {
            let harness = try await harness([("Solo", "ipv6-dual-stack")])
            defer { try? FileManager.default.removeItem(at: harness.root) }
            let solo = try #require(harness.app.shell.profiles.first)
            harness.app.shell.profiles = (0 ... MacTunnelArchive.maximumEntries).map { index in
                var copy = solo; copy.name = "T\(index)"; return copy
            }
            let before = try FileManager.default.contentsOfDirectory(atPath: harness.out.path)
            #expect(await !harness.app.exportAll(to: harness.out.appendingPathComponent("all.zip")))
            #expect(harness.app.exportAllMessage == MacStrings.exportAllTooMany)
            #expect(MacStrings.exportAllTooMany.contains("1,024"))
            #expect(try FileManager.default.contentsOfDirectory(atPath: harness.out.path) == before)
            #expect(!harness.app.exportAllRunning)
        }

        @Test func `a failed export reports fixed copy only and resets state`() async throws {
            let harness = try await harness([("Solo", "ipv6-dual-stack")])
            defer { try? FileManager.default.removeItem(at: harness.root) }
            let missing = harness.out.appendingPathComponent("no-such-directory/x.zip")
            #expect(await !harness.app.exportAll(to: missing))
            #expect(harness.app.exportAllMessage == MacStrings.theConfigurationCouldNotBe)
            #expect(!harness.app.exportAllRunning)
            #expect(await harness.app.exportAll(to: harness.out.appendingPathComponent("x.zip")))
            #expect(harness.app.exportAllMessage == nil)
        }

        @Test func `export all asks for the key warning only when tunnels exist`() async throws {
            let harness = try await harness()
            defer { try? FileManager.default.removeItem(at: harness.root) }
            harness.app.requestExportAll()
            #expect(harness.app.exportAllConfirming)
            harness.app.cancelExportAll()
            #expect(!harness.app.exportAllConfirming)
            harness.app.shell.profiles = []
            harness.app.requestExportAll()
            #expect(!harness.app.exportAllConfirming)
        }

        @Test func `menu bar import opens the window importer and brings the window forward`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root)
            var shown = 0
            app.openImportInMainWindow { shown += 1 }
            #expect(shown == 1)
            #expect(app.importing)
            #expect(app.importReviews.isEmpty)
            #expect(app.importErrorMessage == nil)
            #expect(MacStrings.importTunnelsCommand == "Import Tunnels…")
        }
    }
#endif
