// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
#if os(macOS)
    import Darwin.membership
#endif

private struct PrivilegeHardeningTests {
    @Test
    func `legacy wall clock revisions migrate without exhausting the daemon counter`() async throws {
        let harness = try ControllerHarness()
        let legacy = RegisteredProfile(registration: .init(profile: harness.profile, revision: UInt64.max), ownerUID: 501)
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(legacy)) as? [String: Any])
        object.removeValue(forKey: "revisionIsDaemonOwned")
        try harness.directory.directory("profiles").replace(
            harness.profile.id.uuidString + ".json",
            with: JSONSerialization.data(withJSONObject: object),
        )
        #expect(try await harness.registry.installationRevision(harness.profile.id, connectionUID: 501) == 1)
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        #expect(try repository.load(harness.profile.id)?.revisionIsDaemonOwned == nil)
        var changed = harness.profile; changed.name = "After migration"
        await #expect(throws: DaemonFailure.registryRevisionConflict) {
            try await harness.registry.installProfile(changed, expectedRevision: 99, connectionUID: 501)
        }
        #expect(try repository.load(harness.profile.id)?.revisionIsDaemonOwned == nil)
        #expect(try await harness.registry.installProfile(changed, expectedRevision: 1, connectionUID: 501) == 2)
    }

    @Test
    func `admin Applications ancestor verifies and non admin ACL refuses`() async {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.ancestors = [.init(relativePath: ".", uid: 0, gid: 80, mode: 0o775, kind: .directory)] }
        #expect(await SecureInstall(system: system).status().state == .verified)
        system.state.withLock { $0.ancestors[0].mode = 0o755; $0.ancestors[0].aclWritable = true }
        #expect(await SecureInstall(system: system).status().state == .needsAttention(.aclWritable))
    }

    @Test
    func `CAS revision lookup permits owner repair after a corrupt primary`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        try harness.directory.directory("profiles").replace(harness.profile.id.uuidString + ".json", with: Data("invalid".utf8))
        let context = DaemonRequestContext(
            peer: .init(uid: 501, pid: 9, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id],
            clientBuild: 10,
        )
        #expect(await harness.controller.profileRevision(harness.profile.id, context: context) == .profileRevision(1))
        var repaired = harness.profile; repaired.name = "Repaired fixture"
        #expect(await harness.controller.installProfileCAS(repaired, expectedRevision: 1, context: context) == .profileRevision(2))
    }

    @Test
    func `daemon allocates revisions and stale clients can refresh without clocks`() async throws {
        let harness = try ControllerHarness()
        let registry = harness.registry
        let id = harness.profile.id
        #expect(try await registry.installProfile(harness.profile, expectedRevision: nil, connectionUID: 501) == 1)
        #expect(try await registry.installProfile(harness.profile, expectedRevision: nil, connectionUID: 501) == 1)
        var changed = harness.profile; changed.name = "Edited fixture"
        #expect(try await registry.installProfile(changed, expectedRevision: 1, connectionUID: 501) == 2)
        await #expect(throws: DaemonFailure.registryRevisionConflict) {
            _ = try await registry.installProfile(harness.profile, expectedRevision: 1, connectionUID: 501)
        }
        #expect(try await registry.profile(id, connectionUID: 501).revision == 2)
        #expect(try await registry.installProfile(harness.profile, expectedRevision: 2, connectionUID: 501) == 3)
        await #expect(throws: DaemonFailure.registryNotOwner) {
            _ = try await registry.installProfile(harness.profile, expectedRevision: nil, connectionUID: 502)
        }
    }

    @Test
    func `imported boot flags never create or change daemon boot intent`() async throws {
        let harness = try ControllerHarness()
        var first = harness.profile; first.macOptions.startBeforeLogin = true
        var second = try ControllerHarness.makeProfile(); second.macOptions.startBeforeLogin = true
        _ = try await harness.registry.installProfile(first, expectedRevision: nil, connectionUID: 501)
        _ = try await harness.registry.installProfile(second, expectedRevision: nil, connectionUID: 501)
        #expect(try await harness.registry.bootIntent() == nil)
        try await harness.registry.setStartBeforeLogin(first.id, enabled: true, connectionUID: 501)
        first.macOptions.startBeforeLogin = false
        _ = try await harness.registry.installProfile(first, expectedRevision: 1, connectionUID: 501)
        #expect(try await harness.registry.bootIntent()?.profileID == first.id)
        await #expect(throws: DaemonFailure.registryMultipleBootProfiles) {
            try await harness.registry.setStartBeforeLogin(second.id, enabled: true, connectionUID: 501)
        }
    }

    @Test
    func `ACL write grants are reported even with root POSIX ownership`() async {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[1].aclWritable = true }
        #expect(await SecureInstall(system: system).status().state == .needsAttention(.aclWritable))
    }

    @Test
    func `real temporary ACL is detected and stripped through the same descriptor`() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("wgex-acl-" + UUID().uuidString)
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        let file = root.appendingPathComponent("entry")
        try Data("inert fixture".utf8).write(to: file)
        #if os(macOS)
            try manager.setAttributes([.posixPermissions: 0o6777], ofItemAtPath: file.path)
            var acl: acl_t? = acl_init(1)
            try #require(acl != nil)
            defer {
                if let acl {
                    acl_free(UnsafeMutableRawPointer(acl))
                }
            }
            var grantEntry: acl_entry_t?
            #expect(acl_create_entry(&acl, &grantEntry) == 0)
            let grant = try #require(grantEntry)
            #expect(acl_set_tag_type(grant, ACL_EXTENDED_ALLOW) == 0)
            var trustee = UUID().uuid
            #expect(mbr_uid_to_uuid(getuid(), &trustee) == 0)
            #expect(acl_set_qualifier(grant, &trustee) == 0)
            var permissions: acl_permset_t?
            #expect(acl_get_permset(grant, &permissions) == 0)
            let permissionSet = try #require(permissions)
            #expect(acl_add_perm(permissionSet, ACL_WRITE_DATA) == 0)
            #expect(acl_set_file(file.path, ACL_TYPE_EXTENDED, acl) == 0)
            let bundle = try SecureBundleDescriptor(path: SecureBundleDescriptor.canonicalPath(root.path))
            defer { close(bundle.descriptor) }
            let entry = try #require(bundle.entries().first { $0.relativePath == "entry" })
            #expect(entry.aclWritable)
            try bundle.repair(entry, uid: getuid(), gid: getgid())
            let repaired = try #require(bundle.entries().first { $0.relativePath == "entry" })
            #expect(!repaired.aclWritable)
            #expect(repaired.mode & 0o6022 == 0)
        #endif
    }
}
