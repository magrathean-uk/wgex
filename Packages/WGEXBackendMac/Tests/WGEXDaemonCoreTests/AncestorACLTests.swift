// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore

#if os(macOS)
    import Darwin
    import Darwin.membership
#endif

private struct AncestorACLTests {
    @Test(arguments: [UInt32(80), 20])
    func `real ancestor ACL distinguishes admin and staff grants`(gid: UInt32) throws {
        #if os(macOS)
            let root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-ancestor-acl-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            var acl = acl_init(1)
            try #require(acl != nil)
            defer {
                if let acl {
                    acl_free(UnsafeMutableRawPointer(acl))
                }
            }
            var entry: acl_entry_t?
            try #require(acl_create_entry(&acl, &entry) == 0)
            let grant = try #require(entry)
            try #require(acl_set_tag_type(grant, ACL_EXTENDED_ALLOW) == 0)
            var trustee = UUID().uuid
            try #require(mbr_gid_to_uuid(gid, &trustee) == 0)
            try #require(acl_set_qualifier(grant, &trustee) == 0)
            var permissions: acl_permset_t?
            try #require(acl_get_permset(grant, &permissions) == 0)
            let permissionSet = try #require(permissions)
            try #require(acl_add_perm(permissionSet, ACL_WRITE_DATA) == 0)
            try #require(acl_add_perm(permissionSet, ACL_DELETE_CHILD) == 0)
            try #require(acl_set_file(root.path, ACL_TYPE_EXTENDED, acl) == 0)
            let descriptor = try SecureBundleDescriptor(path: SecureBundleDescriptor.canonicalPath(root.path))
            defer { close(descriptor.descriptor) }
            let ancestor = try descriptor.rootEntry(ancestor: true)
            #expect(ancestor.hasACL && ancestor.aclWritable)
            #expect(ancestor.aclAdminOnly == (gid == 80))
            let bundle = try descriptor.rootEntry()
            #expect(bundle.hasACL && bundle.aclWritable && !bundle.aclAdminOnly)
        #endif
    }
}
