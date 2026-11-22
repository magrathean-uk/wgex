// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Descriptor-relative, no-follow traversal shared by the guarded adapter and temp-only tests.
/// Opening each ancestor separately refuses symlinks in any component, including the bundle root.
package struct SecureBundleDescriptor {
    package let descriptor: Int32

    package init(path: String) throws {
        guard path.hasPrefix("/"), SecureInstall.validRelativePath(String(path.dropFirst())) else {
            throw DaemonFailure.hostSystem(EINVAL)
        }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw DaemonFailure.hostSystem(errno) }
        do {
            for component in path.split(separator: "/") {
                let next = openat(current, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw DaemonFailure.hostSystem(errno) }
                close(current); current = next
            }
            descriptor = current
        } catch { close(current); throw error }
    }

    package func entries() throws -> [SecureInstallEntry] {
        var result = try [rootEntry()]
        try walk(descriptor, prefix: "", result: &result)
        return result
    }

    package func rootEntry(ancestor: Bool = false) throws -> SecureInstallEntry {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw DaemonFailure.hostSystem(errno) }
        var entry = try Self.entry(".", info)
        let acl = try Self.aclAssessment(descriptor, ancestor: ancestor)
        entry.hasACL = acl.present; entry.aclWritable = acl.writable; entry.aclAdminOnly = acl.adminOnly
        return entry
    }

    private func walk(_ directory: Int32, prefix: String, result: inout [SecureInstallEntry]) throws {
        for name in try Self.names(directory) {
            var info = stat()
            guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw DaemonFailure.hostSystem(errno) }
            let path = prefix.isEmpty ? name : prefix + "/" + name
            var entry = try Self.entry(path, info)
            if entry.kind != .symlink {
                let acl = try withEntryDescriptor(entry) { try Self.aclAssessment($0) }
                entry.hasACL = acl.present; entry.aclWritable = acl.writable
            }
            result.append(entry)
            if entry.kind == .directory {
                let child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw DaemonFailure.hostSystem(errno) }
                defer { close(child) }
                var opened = stat()
                guard fstat(child, &opened) == 0, opened.st_ino == info.st_ino, opened.st_dev == info.st_dev else {
                    throw DaemonFailure.hostSystem(ESTALE)
                }
                try walk(child, prefix: path, result: &result)
            }
        }
    }

    /// Foundation can spell the system temporary directory using the /var alias.
    package static func canonicalPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw DaemonFailure.hostSystem(errno) }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func names(_ directory: Int32) throws -> [String] {
        // dup shares the directory stream offset and made a second inspection silently omit children.
        let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0 else { throw DaemonFailure.hostSystem(errno) }
        guard let stream = fdopendir(copy) else { close(copy); throw DaemonFailure.hostSystem(errno) }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let item = readdir(stream) else {
                guard errno == 0 else { throw DaemonFailure.hostSystem(errno) }
                break
            }
            let name = withUnsafePointer(to: &item.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(item.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." {
                names.append(name)
            }
        }
        return names.sorted()
    }

    private static func entry(_ path: String, _ info: stat) throws -> SecureInstallEntry {
        let kind: SecureInstallEntry.Kind
        switch info.st_mode & S_IFMT {
        case S_IFDIR: kind = .directory
        case S_IFREG:
            guard info.st_nlink == 1 else { throw DaemonFailure.hostSystem(EMLINK) }
            kind = .file
        case S_IFLNK: kind = .symlink
        default: throw DaemonFailure.hostSystem(EINVAL)
        }
        var entry = SecureInstallEntry(
            relativePath: path, uid: info.st_uid, gid: info.st_gid, mode: info.st_mode & 0o7777, kind: kind,
        )
        entry.changeStamp = "\(info.st_mtimespec.tv_sec):\(info.st_mtimespec.tv_nsec):\(info.st_ctimespec.tv_sec):\(info.st_ctimespec.tv_nsec)"
        entry.device = UInt64(UInt32(bitPattern: info.st_dev)); entry.inode = info.st_ino
        return entry
    }

    /// Ancestors cannot be swapped for links between enumeration and mutation.
    package func withParent<Result>(_ entry: SecureInstallEntry, body: (Int32, String) throws -> Result) throws -> Result {
        guard SecureInstall.validRelativePath(entry.relativePath) else { throw DaemonFailure.hostSystem(EINVAL) }
        let parts = entry.relativePath.split(separator: "/").map(String.init)
        var current = dup(descriptor)
        guard current >= 0 else { throw DaemonFailure.hostSystem(errno) }
        defer { close(current) }
        for component in parts.dropLast() {
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw DaemonFailure.hostSystem(errno) }
            close(current); current = next
        }
        let name = parts.last ?? "."
        var info = stat()
        guard fstatat(current, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
              info.st_ino == entry.inode, UInt64(UInt32(bitPattern: info.st_dev)) == entry.device,
              info.st_mode & S_IFMT != S_IFREG || info.st_nlink == 1 else { throw DaemonFailure.hostSystem(ESTALE) }
        return try body(current, name)
    }
}
