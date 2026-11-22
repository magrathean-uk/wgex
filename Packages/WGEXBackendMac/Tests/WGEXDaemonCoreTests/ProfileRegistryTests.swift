// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXProfileStore

@Suite(.timeLimit(.minutes(1)))
private struct ProfileRegistryTests {
    @Test
    func `owner comes from connection revisions replay idempotently and conflicting replays fail`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let original = harness.profile
        try await harness.registry.installProfile(original, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        await #expect(throws: DaemonFailure.registryNotOwner) {
            try await harness.registry.installProfile(original, expectedRevision: nil, connectionUID: ControllerHarness.uid + 1)
        }
        await #expect(throws: DaemonFailure.registryNotOwner) {
            try await harness.registry.removeProfile(harness.profile.id, purgeSecrets: true, connectionUID: ControllerHarness.uid + 1)
        }
        var changed = harness.profile; changed.name = "Changed"
        await #expect(throws: DaemonFailure.registryRevisionConflict) {
            try await harness.registry.installProfile(changed, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        }
        try await harness.registry.installProfile(changed, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        await #expect(throws: DaemonFailure.registryRevisionConflict) {
            try await harness.registry.installProfile(original, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        }
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        let restarted = ProfileRegistry(repository: repository, secrets: harness.store, bundles: harness.store)
        #expect(try await restarted.profile(changed.id, connectionUID: ControllerHarness.uid).revision == 2)
        #expect(try repository.all().count == 1)
    }

    @Test
    func `profile validation rejects keychain references and malformed profiles`() async throws {
        let harness = try ControllerHarness()
        var profile = harness.profile; profile.secrets.privateKey = .keychain(persistentRef: Data([1]))
        await #expect(throws: DaemonFailure.registryInvalidSecretReference) {
            try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        }
        profile = harness.profile
        profile.original = OriginalText(text: "untrusted imported text", sha256OfOriginal: Data())
        await #expect(throws: DaemonFailure.registryInvalidProfile) {
            try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        }
        #expect(try harness.directory.directory("profiles").filenames().isEmpty)
        profile = harness.profile; profile.peers = []
        await #expect(throws: DaemonFailure.registryInvalidProfile) {
            try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: ControllerHarness.uid)
        }
    }

    @Test(arguments: [false, true])
    func `removal retires profile before optional secret purge`(purge: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        guard case let .daemonStore(reference) = harness.profile.secrets.privateKey else { Issue.record("Bad fixture"); return }
        let id = SecretID(profileID: harness.profile.id, kind: .privateKey, id: reference)
        try await harness.store.store(ControllerHarness.testKey(), for: id)
        try await harness.registry.removeProfile(harness.profile.id, purgeSecrets: purge, connectionUID: ControllerHarness.uid)
        await #expect(throws: DaemonFailure.registryNotFound) { try await harness.registry.profile(
            harness.profile.id,
            connectionUID: ControllerHarness.uid,
        ) }
        #expect(try await harness.store.exists(id) == !purge)
        if purge {
            await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
        } else {
            let bundle = try await harness.store.loadBundle(profileID: harness.profile.id); #expect(bundle.count > 32)
        }
    }

    @Test
    func `a crash after profile retirement completes the tombstoned purge on restart`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        try repository.stagePurge(RegisteredProfile(
            registration: DaemonProfile(profile: harness.profile, revision: 1),
            ownerUID: ControllerHarness.uid,
        ))
        try repository.remove(harness.profile.id)
        try await harness.registry.reconcilePurges()
        #expect(try repository.pendingPurges().isEmpty)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }
}
