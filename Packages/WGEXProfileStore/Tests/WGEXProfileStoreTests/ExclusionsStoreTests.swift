// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

/// DEC-087: exclusions persist through the store; a version 2 document without them migrates to version 3 with none.
private struct ExclusionsStoreTests {
    @Test
    func `a version 2 document without exclusions loads with none and is rewritten as version 3`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = try ProfileQuarantineTests.fixture(name: "Old")
        let url = directory.appendingPathComponent("profiles").appendingPathComponent(profile.id.uuidString + ".json")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var object = try #require(JSONSerialization.jsonObject(with: ProfileDocument(profile: profile, schemaVersion: 2).encoded())
            as? [String: Any])
        var stored = try #require(object["profile"] as? [String: Any])
        stored.removeValue(forKey: "exclusions")
        object["profile"] = stored
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)

        let loaded = try await ProfileStore(container: directory).load(profile.id)
        #expect(loaded.exclusions == .empty)
        #expect(loaded == profile)
        let migrated = try JSONDecoder().decode(ProfileDocument.self, from: Data(contentsOf: url))
        #expect(migrated.schemaVersion == 3)
    }

    @Test
    func `exclusions survive a save and load`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var profile = try ProfileQuarantineTests.fixture(name: "Excluding")
        profile.exclusions = try TunnelExclusions(entries: ["192.0.2.0/24", "2001:db8:5::/48", "198.51.100.7", "example.com"])
        let store = ProfileStore(container: directory)
        try await store.save(profile)
        #expect(try await ProfileStore(container: directory).load(profile.id).exclusions == profile.exclusions)
    }

    @Test
    func `a version 3 document is refused by a store that only knows version 2`() async throws {
        let directory = try Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = try ProfileQuarantineTests.fixture(name: "Newer")
        let url = directory.appendingPathComponent("profiles").appendingPathComponent(profile.id.uuidString + ".json")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try ProfileDocument(profile: profile, schemaVersion: ProfileDocument.currentSchemaVersion + 1).encoded().write(to: url)
        await #expect(throws: ProfileStoreError.unsupportedVersion(ProfileDocument.currentSchemaVersion + 1)) {
            try await ProfileStore(container: directory).load(profile.id)
        }
    }

    private static func temporaryDirectory() throws -> URL {
        let root = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? FileManager.default.temporaryDirectory
        let url = root.appendingPathComponent("wgex-exclusion-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
