// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

private enum SimulatedFailure: Error { case crash }

private struct ProfileStoreTests {
    @Test
    func `sorted envelope round trip preserves the Core profile version`() throws {
        let document = ProfileDocument(profile: TunnelProfile(name: "Test", createdAt: Date(timeIntervalSince1970: 123)))
        let encoded = try document.encoded()
        #expect(try JSONDecoder().decode(ProfileDocument.self, from: encoded) == document)
        #expect(try document.encoded() == encoded)
        #expect(document.profile.schemaVersion == TunnelProfile.currentSchemaVersion)
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["schemaVersion"] as? Int == 3)
        #expect(String(decoding: encoded, as: UTF8.self).hasPrefix("{\"profile\":"))
    }

    @Test
    func `list load save delete and settings use the specified file layout`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ProfileStore(container: directory)
        #expect(try await store.list().isEmpty)
        #expect(try await store.loadSettings() == SettingsDocument())
        let profile = try ProfileQuarantineTests.fixture(name: "Test")
        try await store.save(profile)
        #expect(FileManager.default.fileExists(atPath: Self.profileURL(profile.id, in: directory).path))
        #expect(try await store.list() == [profile])
        #expect(try await store.load(profile.id) == profile)
        let settings = SettingsDocument(
            macGlobal: MacGlobalSettings(lockdown: true, allowLAN: false, captiveWindowSeconds: 120, notifications: false),
            app: AppSettings(selectedProfileID: profile.id),
        )
        try await store.saveSettings(settings)
        #expect(try await store.loadSettings() == settings)
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent("settings.json").path))
        try await store.delete(profile.id)
        #expect(try await store.list().isEmpty)
        await #expect(throws: ProfileStoreError.notFound) { try await store.load(profile.id) }
        await #expect(throws: ProfileStoreError.notFound) { try await store.delete(profile.id) }
    }

    @Test
    func `crash after fsync before rename keeps previous document byte for byte`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ProfileStore(container: directory)
        var profile = try ProfileQuarantineTests.fixture(name: "Old")
        try await store.save(profile)
        let url = Self.profileURL(profile.id, in: directory)
        let previous = try Data(contentsOf: url)
        let crashing = ProfileStore(container: directory, writeHook: { point, candidate in
            if case .temporaryFileSynced = point {
                #expect(candidate.deletingLastPathComponent() == url.deletingLastPathComponent())
                #expect(FileManager.default.fileExists(atPath: candidate.path))
                throw SimulatedFailure.crash
            }
        })
        profile.name = "New"
        await #expect(throws: SimulatedFailure.crash) { try await crashing.save(profile) }
        #expect(try Data(contentsOf: url) == previous)
        #expect(try await store.load(profile.id).name == "Old")
        #expect(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path).count == 1)
    }

    @Test(arguments: [0, 1, 2])
    func `migration publishes only after candidate read back succeeds`(readBackFailure: Int) async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = try ProfileQuarantineTests.fixture(name: "Version one")
        let url = Self.profileURL(profile.id, in: directory)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let previous = try ProfileDocument(profile: profile, schemaVersion: 1).encoded()
        try previous.write(to: url)
        let store = ProfileStore(container: directory, writeHook: { point, candidate in
            if case .beforeMigrationReadBack = point {
                #expect(try Data(contentsOf: url) == previous)
                if readBackFailure != 0 {
                    try Data("{}".utf8).write(to: candidate)
                }
            }
        })
        if readBackFailure != 0 {
            await #expect(throws: (any Error).self) { try await store.load(profile.id) }
            #expect(try Data(contentsOf: url) == previous)
            #expect(try await ProfileStore(container: directory).load(profile.id) == profile)
        } else {
            #expect(try await store.load(profile.id) == profile)
            let migrated = try JSONDecoder().decode(ProfileDocument.self, from: Data(contentsOf: url))
            #expect(migrated.schemaVersion == ProfileDocument.currentSchemaVersion)
        }
    }

    @Test
    func `serialized concurrent writers leave a complete document`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ProfileStore(container: directory)
        let id = UUID()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 40 {
                group.addTask { try await store.save(ProfileQuarantineTests.fixture(id: id, name: "Profile \(index)")) }
            }
            try await group.waitForAll()
        }
        let profile = try await store.load(id)
        #expect(profile.name.hasPrefix("Profile "))
        #expect(try await store.list().count == 1)
    }

    @Test(arguments: [0, 4])
    func `unknown schema versions never overwrite disk`(version: Int) async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = try ProfileQuarantineTests.fixture(name: "Unknown")
        let url = Self.profileURL(profile.id, in: directory)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try ProfileDocument(profile: profile, schemaVersion: version).encoded()
        try data.write(to: url)
        let store = ProfileStore(container: directory)
        await #expect(throws: ProfileStoreError.unsupportedVersion(version)) { try await store.load(profile.id) }
        #expect(try Data(contentsOf: url) == data)
    }

    @Test
    func `invalid and missing migration chains preserve the source`() throws {
        let old = try ProfileDocument(profile: ProfileQuarantineTests.fixture(name: "Old"), schemaVersion: 1)
        let invalid = Migration(fromVersion: 1, toVersion: 3) { $0 }
        #expect(throws: ProfileStoreError.invalidMigration) { try invalid.apply(old) }
        let unchanged = Migration(fromVersion: 1, toVersion: 2) { $0 }
        #expect(throws: ProfileStoreError.invalidMigration) { try unchanged.apply(old) }
    }

    @Test(arguments: [false, true])
    func `missing and ambiguous migration chains preserve version one`(ambiguous: Bool) async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = try ProfileQuarantineTests.fixture(name: "Old")
        let url = Self.profileURL(profile.id, in: directory)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let previous = try ProfileDocument(profile: profile, schemaVersion: 1).encoded()
        try previous.write(to: url)
        let migrations = ambiguous ? Migration.standard + Migration.standard : []
        let store = ProfileStore(container: directory, migrations: migrations)
        await #expect(throws: ProfileStoreError.invalidMigration) { try await store.load(profile.id) }
        #expect(try Data(contentsOf: url) == previous)
    }

    @Test
    func `journal vocabulary and references round trip without secret material`() throws {
        let profileID = UUID()
        let journal = Journal(entries: [JournalEntry(
            profileID: profileID, operation: .rotateSecret, completedSteps: JournalEntry.Step.allCases,
            oldSecret: SecretID(profileID: profileID, kind: .privateKey),
            stagedSecret: SecretID(profileID: profileID, kind: .privateKey),
        )])
        #expect(JournalEntry.Step.allCases == [.stageSecret, .writeProfile, .installIntoBackend, .verify, .retireOldSecret])
        #expect(try JSONDecoder().decode(Journal.self, from: JSONEncoder().encode(journal)) == journal)
    }

    @Test
    func `an incomplete document loads only behind the opt-in`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var profile = try ProfileQuarantineTests.fixture(name: "Blank")
        profile.interface.addresses = []
        profile.peers = []
        try await ProfileStore(container: directory).save(profile)
        let strict = ProfileStore(container: directory)
        #expect(try await strict.list().isEmpty)
        #expect(await strict.takeQuarantinedProfiles() == [profile.id])
        await #expect(throws: ProfileStoreError.invalidDocument) { try await strict.load(profile.id) }
        let admitting = ProfileStore(container: directory, admitsIncomplete: true)
        #expect(try await admitting.list() == [profile])
        #expect(await admitting.takeQuarantinedProfiles().isEmpty)
        // Every other check still applies: an empty name is quarantined even with the opt-in.
        var unnamed = profile
        unnamed.name = ""
        try await admitting.save(unnamed)
        #expect(try await ProfileStore(container: directory, admitsIncomplete: true).list().isEmpty)
    }

    private static func temporaryDirectory() throws -> URL {
        let root = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? FileManager.default.temporaryDirectory
        let url = root.appendingPathComponent("wgex-profile-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private static func profileURL(_ id: UUID, in directory: URL) -> URL {
        directory.appendingPathComponent("profiles").appendingPathComponent(id.uuidString + ".json")
    }
}
