// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXProfileStore

@Suite(.timeLimit(.minutes(1)))
private struct VerifierRemediationTests {
    @Test(arguments: [UInt32(80), 20, 0])
    func `only admin group write is accepted for an Applications ancestor`(gid: UInt32) async {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.ancestors = [.init(relativePath: ".", uid: 0, gid: gid, mode: 0o775, kind: .directory)] }
        let result = await SecureInstall(system: system).status()
        #expect(result.state == (gid == 80 ? .verified : .needsAttention(.bundleWritable)))
    }

    @Test
    func `ancestor admin policy never relaxes bundle ownership mode or ACLs`() async {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[0].gid = 80 }
        #expect(await SecureInstall(system: system).status().state == .needsAttention(.notRootOwned))
        system.state.withLock { $0.entries[0].gid = 0; $0.entries[0].hasACL = true }
        #expect(await SecureInstall(system: system).status().state == .needsAttention(.aclWritable))
        system.state.withLock { $0.entries[0].hasACL = false; $0.entries[0].mode = 0o775 }
        #expect(await SecureInstall(system: system).status().state == .needsAttention(.bundleWritable))
    }

    @Test(arguments: [false, true])
    func `ancestor ACL permits admin principals only`(adminOnly: Bool) async {
        let system = FakeSecureInstallSystem()
        var parent = SecureInstallEntry(relativePath: ".", uid: 0, gid: 80, mode: 0o775, kind: .directory)
        parent.aclWritable = true; parent.aclAdminOnly = adminOnly
        system.state.withLock { $0.ancestors = [parent] }
        #expect(await SecureInstall(system: system).status().state == (adminOnly ? .verified : .needsAttention(.aclWritable)))
    }

    @Test
    func `key validation is cached and explicitly invalidated`() async {
        let calls = Mutex(0)
        let install = SecureInstall(system: FakeSecureInstallSystem(), validateKey: { calls.withLock { $0 += 1 } })
        _ = await install.status(); _ = await install.status()
        #expect(calls.withLock { $0 } == 1)
        await install.invalidate()
        _ = await install.status()
        #expect(calls.withLock { $0 } == 2)
        _ = await install.perform(); _ = await install.status()
        #expect(calls.withLock { $0 } == 3)
    }

    @Test
    func `fingerprint failure cannot prevent encrypted bundle save or load`() async throws {
        let harness = try ControllerHarness()
        let calls = Mutex(0)
        let store = try DaemonSecretStore(
            directory: harness.directory,
            keyProvider: InMemoryDaemonKeyProvider(key: ControllerHarness.testKey()),
            observeBundle: { _ in calls.withLock { $0 += 1 }; throw HostTestError.injected },
        )
        let wire = try ControllerHarness.bundle().wireBytes()
        try await store.saveBundle(wire, profileID: harness.profile.id)
        let loaded = try await store.loadBundle(profileID: harness.profile.id)
        #expect(loaded.count > 32)
        #expect(calls.withLock { $0 } == 2)
    }

    @Test
    func `readable legacy ACL warns and repair preserves the key`() throws {
        let warnings = Mutex(0)
        let read = WrappingKeyReadPolicy(read: { try ControllerHarness.testKey() }, legacyAccess: { true }, warnLegacy: {
            warnings.withLock { $0 += 1 }
        })
        let key = try read.wrappingKey()
        let fixture = try ControllerHarness.testKey()
        let same = key.constantTimeEquals(fixture)
        #expect(same && warnings.withLock { $0 } == 1)
        let repaired = Mutex(false)
        let provisioner = WrappingKeyProvisioner(read: {
            guard repaired.withLock({ $0 }) else { throw SecretStoreError.locked }
            return try ControllerHarness.testKey()
        }, create: { _ in Issue.record("Existing key must not be replaced") }, generate: {
            Issue.record("Existing key must not be generated again"); return try ControllerHarness.testKey()
        }, repairAccess: { repaired.withLock { $0 = true } })
        try provisioner.provision()
        let after = try provisioner.wrappingKey()
        let unchanged = after.constantTimeEquals(fixture)
        #expect(unchanged)
    }

    @Test
    func `profile qualification cache remains usable without repository reads`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        let cached = await harness.registry.cachedDNSConfigured(harness.profile.id)
        #expect(cached == true)
        try harness.directory.directory("profiles").replace(harness.profile.id.uuidString + ".json", with: Data("invalid".utf8))
        #expect(await harness.registry.cachedDNSConfigured(harness.profile.id) == true)
        try await harness.registry.removeProfile(harness.profile.id, purgeSecrets: false, connectionUID: 501)
        #expect(await harness.registry.cachedDNSConfigured(harness.profile.id) == nil)
    }

    @Test
    func `legacy migration uses the controller recovery generation barrier`() async throws {
        let harness = try ControllerHarness()
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        try repository.save(.init(
            registration: .init(profile: harness.profile, revision: UInt64.max),
            ownerUID: 501,
            revisionIsDaemonOwned: nil,
        ))
        let before = await harness.controller.generation
        let context = DaemonRequestContext(
            peer: .init(uid: 501, pid: 9, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id],
            clientBuild: 10,
            expectedGeneration: nil,
        )
        var changed = harness.profile; changed.name = "Migrated through barrier"
        #expect(await harness.controller.installProfileCAS(changed, expectedRevision: 1, context: context) == .profileRevision(2))
        #expect(await harness.controller.generation != before)
        #expect(try repository.load(harness.profile.id)?.revisionIsDaemonOwned == true)
    }

    @Test
    func `pushed protected status is qualified before delivery through the publish queue`() async throws {
        let harness = try ControllerHarness()
        var profile = harness.profile; profile.interface.dns = []
        _ = try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        let dispatcher = DaemonDispatcher(service: harness.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1)
        let (stream, continuation) = AsyncStream<Event>.makeStream()
        let transport = InMemoryXPCTransport(
            daemon: dispatcher,
            peer: .init(uid: 501, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init(event: { data in
            if let event = try? WireCodec.decode(Event.self, from: data) {
                continuation.yield(event)
            }
        }))
        _ = try await transport.send(Envelope(body: .hello(clientVersion: "test", clientBuild: 10)).encoded(), secrets: nil)
        _ = try await transport.send(Envelope(body: .subscribeEvents(includeLogs: false)).encoded(), secrets: nil)
        var status = TunnelStatus.idle; status.protection = .protected
        status.phase = .active(Generation(rawValue: 91))
        await dispatcher.publish(.status(status), profileID: profile.id, ownerUID: 501)
        var iterator = stream.makeAsyncIterator()
        while let event = await iterator.next() {
            if case let .status(delivered) = event, delivered.phase == status.phase {
                #expect(delivered.protection == .unknown)
                continuation.finish()
                return
            }
        }
        Issue.record("Missing pushed status with the published generation")
        continuation.finish()
    }
}
