// SPDX-License-Identifier: MIT
import Darwin
import WGEXDaemonProtocol
#if os(macOS)
    import Darwin.membership
#endif

package extension SecureBundleDescriptor {
    /// Stat plus ACL enumeration avoids changing credentials. Unknown trustees fail closed.
    /// Bundle entries reject every ACL; ancestors allow mutation only for root/admin trustees.
    static func aclAssessment(_ descriptor: Int32, ancestor: Bool = false) throws -> (present: Bool, writable: Bool, adminOnly: Bool) {
        #if os(macOS)
            guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
                if errno == ENOENT {
                    return (false, false, false)
                }
                throw DaemonFailure.hostSystem(errno)
            }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            var selector = Int32(ACL_FIRST_ENTRY.rawValue)
            var present = false; var writable = false; var adminOnly = true
            while true {
                let result = acl_get_entry(acl, selector, &entry)
                if result != 0 {
                    guard errno == EINVAL || errno == ENOENT else { throw DaemonFailure.hostSystem(errno) }
                    return (present, writable, writable && adminOnly)
                }
                present = true; selector = Int32(ACL_NEXT_ENTRY.rawValue)
                guard let entry else { throw DaemonFailure.hostSystem(EINVAL) }
                if try aclEntryAllowsMutation(entry) {
                    writable = true
                    if !ancestor || !aclTrusteeIsAdmin(entry) {
                        adminOnly = false
                    }
                }
            }
        #else
            return (false, false, false)
        #endif
    }

    static func aclAllowsMutation(_ descriptor: Int32) throws -> Bool {
        try aclAssessment(descriptor).writable
    }

    #if os(macOS)
        private static func aclTrusteeIsAdmin(_ entry: acl_entry_t) -> Bool {
            guard let qualifier = acl_get_qualifier(entry) else { return false }
            defer { acl_free(qualifier) }
            let trustee = qualifier.assumingMemoryBound(to: UInt8.self)
            var identifier: id_t = 0; var type: Int32 = 0
            guard mbr_uuid_to_id(trustee, &identifier, &type) == 0 else { return false }
            if type == ID_TYPE_GID {
                return identifier == 80
            }
            guard type == ID_TYPE_UID else { return false }
            if identifier == 0 {
                return true
            }
            var admin: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            var member: Int32 = 0
            guard mbr_gid_to_uuid(80, &admin) == 0,
                  mbr_check_membership(trustee, &admin, &member) == 0 else { return false }
            return member == 1
        }

        private static func aclEntryAllowsMutation(_ entry: acl_entry_t) throws -> Bool {
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(entry, &tag) == 0 else { throw DaemonFailure.hostSystem(errno) }
            guard tag == ACL_EXTENDED_ALLOW else { return false }
            var permissions: acl_permset_t?
            guard acl_get_permset(entry, &permissions) == 0, let permissions else { throw DaemonFailure.hostSystem(errno) }
            for permission in [
                ACL_WRITE_DATA,
                ACL_APPEND_DATA,
                ACL_DELETE,
                ACL_DELETE_CHILD,
                ACL_WRITE_ATTRIBUTES,
                ACL_WRITE_EXTATTRIBUTES,
                ACL_WRITE_SECURITY,
                ACL_CHANGE_OWNER,
            ] {
                let present = acl_get_perm_np(permissions, permission)
                guard present >= 0 else { throw DaemonFailure.hostSystem(errno) }
                if present == 1 {
                    return true
                }
            }
            return false
        }
    #endif

    /// The same pinned descriptor is used for mode, ACL and owner repair, then read back.
    func repair(_ entry: SecureInstallEntry, uid: UInt32, gid: UInt32) throws {
        try withEntryDescriptor(entry) { fd in
            if entry.kind == .symlink {
                // Link modes/ACLs do not grant access to the target; replacement is checked on the parent.
                guard fchown(fd, uid, gid) == 0 else { throw DaemonFailure.hostSystem(errno) }
                var info = stat()
                guard fstat(fd, &info) == 0, info.st_uid == uid, info.st_gid == gid else { throw DaemonFailure.hostSystem(EPERM) }
                return
            }
            #if os(macOS)
                guard let empty = acl_init(0) else { throw DaemonFailure.hostSystem(errno) }
                defer { acl_free(UnsafeMutableRawPointer(empty)) }
                guard acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED) == 0 else { throw DaemonFailure.hostSystem(errno) }
            #endif
            let mode = entry.installedMode
            guard fchmod(fd, mode) == 0, fchown(fd, uid, gid) == 0 else { throw DaemonFailure.hostSystem(errno) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == uid, info.st_gid == gid,
                  info.st_mode & 0o7777 == mode, try !Self.aclAssessment(fd).present else { throw DaemonFailure.hostSystem(EPERM) }
        }
    }

    /// O_NONBLOCK refuses to hang on a swapped FIFO; fstat rejects substituted types and hard links.
    func withEntryDescriptor<Result>(_ entry: SecureInstallEntry, body: (Int32) throws -> Result) throws -> Result {
        try withParent(entry) { parent, name in
            #if os(macOS)
                let linkFlag = entry.kind == .symlink ? O_SYMLINK : 0
            #else
                let linkFlag: Int32 = 0
            #endif
            let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | linkFlag)
            guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
            defer { close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_ino == entry.inode,
                  UInt64(UInt32(bitPattern: info.st_dev)) == entry.device,
                  info.st_mode & S_IFMT != S_IFREG || info.st_nlink == 1,
                  (info.st_mode & S_IFMT == S_IFLNK) == (entry.kind == .symlink),
                  (info.st_mode & S_IFMT == S_IFDIR) == (entry.kind == .directory) else { throw DaemonFailure.hostSystem(ESTALE) }
            return try body(fd)
        }
    }
}
