// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

private struct M114SchemaTests {
    @Test
    func `unknown core schema is rejected on load`() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ProfileStore(container: directory)
        var profile = TunnelProfile(name: "Schema fixture")
        profile.schemaVersion = TunnelProfile.currentSchemaVersion + 1
        try await store.save(profile)
        await #expect(throws: ConfigurationError.unsupportedSchema(profile.schemaVersion)) { try await store.load(profile.id) }
    }
}
