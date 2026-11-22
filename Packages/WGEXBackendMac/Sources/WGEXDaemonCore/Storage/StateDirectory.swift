// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Numeric write evidence only; no state document or ownership value enters observations.
package struct StateDirectoryWrite: Sendable {
    package let name: String
    package let bytes: Int
    package let durable: Bool
    package var maximumWriteSize: Int {
        min(bytes, 4096)
    }
}

/// An owned directory descriptor. All descendants are opened relative to it; links are never followed.
/// Accepts the production state root or descendants of the process's canonical temporary directory.
public final class StateDirectory: Sendable {
    public let root: URL
    public let ownerUID: uid_t
    private let descriptor: Int32
    private static let maximumFileSize = 8 << 20
    private let observe: @Sendable (StateDirectoryWrite) throws -> Void

    public convenience init(root: URL, ownerUID: uid_t = geteuid()) throws {
        try self.init(root: root, ownerUID: ownerUID, observingWrites: { _ in })
    }

    package init(
        root: URL, ownerUID: uid_t = geteuid(), observingWrites: @escaping @Sendable (StateDirectoryWrite) throws -> Void,
    ) throws {
        let path = root.path
        let temporary = try Self.temporaryRoot().path
        guard Self.permits(path: path, temporaryRoot: temporary) else { throw DaemonFailure.stateUnsafePath }
        let components = path.split(separator: "/").map(String.init)
        guard path.hasPrefix("/"), !components.isEmpty, !components.contains(".."), !components.contains(".") else {
            throw DaemonFailure.stateUnsafePath
        }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw DaemonFailure.stateSystem(errno) }
        do {
            for (index, component) in components.enumerated() {
                let last = index == components.count - 1
                if last, mkdirat(parent, component, 0o700) != 0, errno != EEXIST {
                    throw DaemonFailure.stateSystem(errno)
                }
                let next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                guard next >= 0 else { throw DaemonFailure.stateUnsafePath }
                close(parent); parent = next
            }
            try Self.check(parent, uid: ownerUID, directory: true)
        } catch {
            close(parent); throw error
        }
        descriptor = parent; self.root = root; self.ownerUID = ownerUID; observe = observingWrites
    }

    /// Pure path policy; tests never open the host's production state directory.
    package static func permits(path: String, temporaryRoot: String) -> Bool {
        let systemRoots = ["/Library/Application Support/WGEX", "/System/Volumes/Data/Library/Application Support/WGEX"]
        return path.hasPrefix(temporaryRoot + "/") || systemRoots.contains { path == $0 || path.hasPrefix($0 + "/") }
    }

    /// Canonicalise only the OS-provided scratch ancestor, never an injected state root or descendant.
    /// Foundation deliberately normalises /private/var back to /var on macOS; POSIX realpath retains the no-link path.
    public static func temporaryRoot() throws -> URL {
        let path = ProcessInfo.processInfo.environment["TMPDIR"] ?? FileManager.default.temporaryDirectory.path
        guard let canonical = realpath(path, nil) else { throw DaemonFailure.stateSystem(errno) }
        defer { free(canonical) }
        return URL(fileURLWithPath: String(cString: canonical), isDirectory: true)
    }

    private init(root: URL, ownerUID: uid_t, descriptor: Int32, observe: @escaping @Sendable (StateDirectoryWrite) throws -> Void) {
        self.root = root; self.ownerUID = ownerUID; self.descriptor = descriptor; self.observe = observe
    }

    deinit { close(descriptor) }

    public func directory(_ name: String) throws -> StateDirectory {
        try Self.validate(name)
        if mkdirat(descriptor, name, 0o700) != 0, errno != EEXIST {
            throw DaemonFailure.stateSystem(errno)
        }
        let child = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard child >= 0 else { throw DaemonFailure.stateUnsafePath }
        do { try Self.check(child, uid: ownerUID, directory: true) }
        catch { close(child); throw error }
        return StateDirectory(root: root.appendingPathComponent(name), ownerUID: ownerUID, descriptor: child, observe: observe)
    }

    public func filenames() throws -> [String] {
        let copy = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard copy >= 0 else { throw DaemonFailure.stateSystem(errno) }
        guard let stream = fdopendir(copy) else { close(copy); throw DaemonFailure.stateSystem(errno) }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." {
                names.append(name)
            }
        }
        return names.sorted()
    }

    public func read(_ name: String) throws -> Data? {
        try Self.validate(name)
        let file = openat(descriptor, name, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        if file < 0, errno == ENOENT {
            return nil
        }
        guard file >= 0 else { throw DaemonFailure.stateUnsafePath }
        defer { close(file) }
        try Self.check(file, uid: ownerUID, directory: false)
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR {
                continue
            }
            guard count >= 0 else { throw DaemonFailure.stateSystem(errno) }
            if count == 0 {
                return result
            }
            guard result.count + count <= Self.maximumFileSize else { throw DaemonFailure.stateTooLarge }
            result.append(contentsOf: buffer.prefix(count))
        }
    }

    public func replace(_ name: String, with data: Data) throws {
        try replace(name, with: data, beforeRename: {})
    }

    /// The hook models power loss before publication, without changing the old file.
    package func replace(_ name: String, with data: Data, beforeRename: () throws -> Void) throws {
        try replace(name, with: data, durable: true, beforeRename: beforeRename)
    }

    /// Journal bookkeeping can defer durability until the next resource, policy or token fence.
    package func replace(_ name: String, with data: Data, durable: Bool, beforeRename: () throws -> Void = {}) throws {
        try Self.validate(name)
        guard data.count <= Self.maximumFileSize else { throw DaemonFailure.stateTooLarge }
        try observe(.init(name: name, bytes: data.count, durable: durable))
        _ = try read(name) // Refuse an existing link, foreign owner, hard link or permissive file.
        let temporary = ".write-" + UUID().uuidString
        let file = openat(descriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw DaemonFailure.stateUnsafePath }
        defer { close(file); unlinkat(descriptor, temporary, 0) }
        try Self.check(file, uid: ownerUID, directory: false)
        try Self.write(data, to: file)
        if durable, fsync(file) != 0 {
            throw DaemonFailure.stateSystem(errno)
        }
        try beforeRename()
        // Recheck immediately before publication; the directory is writable by its owner only.
        _ = try read(name)
        guard renameat(descriptor, temporary, descriptor, name) == 0 else { throw DaemonFailure.stateSystem(errno) }
        if durable, fsync(descriptor) != 0 {
            throw DaemonFailure.stateSystem(errno)
        }
    }

    /// Appends one framed transaction, rolling back short writes before another transaction can follow.
    package func append(_ name: String, with data: Data, durable: Bool, beforeCommit: () throws -> Void = {}) throws {
        try Self.validate(name)
        guard data.count <= Self.maximumFileSize else { throw DaemonFailure.stateTooLarge }
        try observe(.init(name: name, bytes: data.count, durable: durable))
        let file = openat(descriptor, name, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw DaemonFailure.stateUnsafePath }
        defer { close(file) }
        try Self.check(file, uid: ownerUID, directory: false)
        let size = lseek(file, 0, SEEK_END)
        guard size >= 0, size + off_t(data.count) <= off_t(Self.maximumFileSize) else { throw DaemonFailure.stateTooLarge }
        do {
            try Self.write(data, to: file)
            try beforeCommit()
            if durable {
                try synchronise(file)
            }
        } catch {
            guard ftruncate(file, size) == 0 else { throw DaemonFailure.stateRollbackFailed(errno) }
            if durable {
                guard fsync(file) == 0 else { throw DaemonFailure.stateRollbackFailed(errno) }
            }
            throw error
        }
    }

    /// Repairs only an incomplete final transaction or clears a log after its checkpoint is durable.
    package func truncate(_ name: String, to size: Int, durable: Bool) throws {
        try Self.validate(name)
        guard size >= 0 else { throw DaemonFailure.stateInvalidDocument }
        let file = openat(descriptor, name, O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        if file < 0, errno == ENOENT, size == 0 {
            return
        }
        guard file >= 0 else { throw DaemonFailure.stateUnsafePath }
        defer { close(file) }
        try Self.check(file, uid: ownerUID, directory: false)
        guard lseek(file, 0, SEEK_END) >= off_t(size), ftruncate(file, off_t(size)) == 0 else { throw DaemonFailure.stateSystem(errno) }
        if durable {
            try synchronise(file)
        }
    }

    private func synchronise(_ file: Int32) throws {
        guard fsync(file) == 0, fsync(descriptor) == 0 else { throw DaemonFailure.stateSystem(errno) }
    }

    private static func write(_ data: Data, to file: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress?.advanced(by: offset), min(4096, bytes.count - offset))
                if count < 0, errno == EINTR {
                    continue
                }
                guard count > 0 else { throw DaemonFailure.stateSystem(errno) }
                offset += count
            }
        }
    }

    public func remove(_ name: String) throws {
        guard try read(name) != nil else { return }
        guard unlinkat(descriptor, name, 0) == 0, fsync(descriptor) == 0 else { throw DaemonFailure.stateSystem(errno) }
    }

    /// Removes every file below this directory except the top-level names in `keeping` (M05-T07 purge). Subdirectories
    /// stay, emptied, because the stores hold them open; a link is removed as an entry and never followed.
    package func removeFiles(keeping: Set<String> = []) throws {
        for name in try filenames() where !keeping.contains(name) {
            var info = stat()
            guard fstatat(descriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                guard errno == ENOENT else { throw DaemonFailure.stateSystem(errno) }
                continue
            }
            if info.st_mode & S_IFMT == S_IFDIR {
                try directory(name).removeFiles()
            } else if unlinkat(descriptor, name, 0) != 0, errno != ENOENT {
                throw DaemonFailure.stateSystem(errno)
            }
        }
        guard fsync(descriptor) == 0 else { throw DaemonFailure.stateSystem(errno) }
    }

    private static func validate(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw DaemonFailure.stateUnsafePath
        }
    }

    private static func check(_ file: Int32, uid: uid_t, directory: Bool) throws {
        var info = stat()
        guard fstat(file, &info) == 0 else { throw DaemonFailure.stateSystem(errno) }
        let kind = directory ? S_IFDIR : S_IFREG
        let mode: mode_t = directory ? 0o700 : 0o600
        guard info.st_uid == uid, info.st_mode & S_IFMT == kind, info.st_mode & 0o7777 == mode,
              directory || info.st_nlink == 1 else { throw DaemonFailure.stateUnsafeMetadata }
    }
}
