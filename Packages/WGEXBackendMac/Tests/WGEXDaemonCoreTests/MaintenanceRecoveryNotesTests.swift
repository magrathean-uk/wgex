// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct MaintenanceRecoveryNotesTests {
    @Test
    func `startup preparation clears the clean marker before policy side effects`() async throws {
        let harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) { $0.cleanShutdownAt = Date() }
        try await harness.controller.prepareStartupBlocking()
        #expect(harness.journal.snapshot().cleanShutdownAt == nil)
    }

    @Test
    func `repeated failure publication from runtime does not run the canary twice`() async throws {
        let harness = try ControllerHarness(underlay: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []))
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        try harness.journal.mutate(generation: nil) { $0.settings = settings }
        let controller = try harness.replacementController()
        // Explicitly remove the primary on the replacement as well.
        await controller.updateStartupUnderlay(.init(
            snapshot: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []),
            satisfied: false,
            mtu: 1500,
        ))
        let revision = await controller.startupControlRevision()
        await #expect(throws: DaemonFailure.startup(.noPrimaryInterface)) { try await controller.reconcileAtStartup() }
        let count = await harness.ports.canaryChecks
        try await controller.recoveryFailed(.noPrimaryInterface, expectedControlID: revision)
        #expect(await harness.ports.canaryChecks == count)
    }

    @Test
    func `missing profile removal returns profileNotFound over service`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        let id = UUID()
        #expect(try await fixture.call(.removeProfile(id, purgeSecrets: false)) == .error(.profileNotFound(id)))
    }

    @Test(arguments: [false, true])
    func `legacy profile without backup is removable by recorded owner despite invalid profile fields`(_ active: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        if active {
            _ = try await harness.start()
        }
        let profiles = try harness.directory.directory("profiles")
        try profiles.remove(harness.profile.id.uuidString + ".repair")
        let name = harness.profile.id.uuidString + ".json"
        let bytes = try #require(try profiles.read(name))
        var json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        var registration = try #require(json["registration"] as? [String: Any])
        var profile = try #require(registration["profile"] as? [String: Any])
        profile["interface"] = "corrupt legacy field"
        registration["profile"] = profile; json["registration"] = registration
        try profiles.replace(name, with: JSONSerialization.data(withJSONObject: json))
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        #expect(try await fixture.call(.removeProfile(harness.profile.id, purgeSecrets: false)) == .ok)
        #expect(try profiles.read(name) == nil)
    }

    @Test
    func `numeric reference timestamps are ages rather than wall clocks`() throws {
        let rows = try PacketFilterReadback.references("123 pfctl 99 5\n")
        let row = try #require(rows.first)
        let now = Date(timeIntervalSince1970: 1_700_000_100)
        #expect(row.age == 5)
        #expect(row.matchesAttempt(at: now.addingTimeInterval(-6), now: now))
        #expect(!row.matchesAttempt(at: now, now: now))
    }
}
