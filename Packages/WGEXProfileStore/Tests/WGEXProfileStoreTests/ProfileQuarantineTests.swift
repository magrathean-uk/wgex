// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

package struct ProfileQuarantineTests {
    @Test package func `one corrupt profile is quarantined once while valid profiles remain readable`() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-quarantine-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ProfileStore(container: root)
        let good = try Self.fixture()
        try await store.save(good)
        let bad = UUID()
        let url = root.appendingPathComponent("profiles/\(bad.uuidString).json")
        try Data("{broken".utf8).write(to: url)
        #expect(try await store.list() == [good])
        #expect(await store.takeQuarantinedProfiles() == [bad])
        #expect(try await store.list() == [good])
        #expect(await store.takeQuarantinedProfiles().isEmpty)
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test(arguments: ["oversized", "invalid", "unknownProfileVersion", "unknownEnvelopeVersion"])
    package func `load rejects oversized invalid and future documents`(_ fault: String) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-load-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ProfileStore(container: root)
        var profile = try Self.fixture()
        if fault == "invalid" {
            profile.interface.addresses = []
        }
        if fault == "unknownProfileVersion" {
            profile.schemaVersion = 99
        }
        try await store.save(profile)
        let url = root.appendingPathComponent("profiles/\(profile.id.uuidString).json")
        if fault == "oversized" {
            try Data(repeating: 32, count: 1_048_577).write(to: url)
        }
        if fault == "unknownEnvelopeVersion" {
            try ProfileDocument(profile: profile, schemaVersion: 99).encoded().write(to: url)
        }
        await #expect(throws: (any Error).self) { try await store.load(profile.id) }
        #expect(try await store.list().isEmpty)
        #expect(await store.takeQuarantinedProfiles() == [profile.id])
    }

    package static func fixture(id: UUID? = nil, name: String = "Stored") throws -> TunnelProfile {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var bytes = try Array(Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/conf/ipv6-dual-stack.conf")))
        let parsed = try parseWgQuick(&bytes, name: name)
        let source = parsed.profile
        return TunnelProfile(
            id: id ?? source.id,
            name: name,
            interface: source.interface,
            peers: source.peers,
            secrets: source.secrets,
            protection: source.protection,
        )
    }
}
