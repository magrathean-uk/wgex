// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import Foundation

    /// File metadata the lab guard needs, from `lstat` (symbolic links are not followed).
    public struct LabMarkerStatus: Sendable, Hashable {
        /// True for a regular file (not a link, directory or device).
        public var isRegularFile: Bool
        /// Owner uid.
        public var ownerUID: uid_t
        /// Permission bits (`st_mode & 07777`).
        public var permissions: UInt16

        /// Creates a status.
        public init(isRegularFile: Bool, ownerUID: uid_t, permissions: UInt16) {
            self.isRegularFile = isRegularFile
            self.ownerUID = ownerUID
            self.permissions = permissions
        }
    }

    /// Read-only access to the lab marker; injected so the guard can be tested.
    public protocol LabMarkerInspecting: Sendable {
        /// Metadata of `path`, or nil when it does not exist.
        func status(atPath path: String) -> LabMarkerStatus?
        /// Up to `limit` bytes of `path`, or nil when unreadable or larger.
        func contents(atPath path: String, limit: Int) -> Data?
    }

    /// The real file system (read-only).
    public struct SystemLabMarkerInspector: LabMarkerInspecting {
        /// Creates an inspector.
        public init() {}

        /// `lstat` of `path`.
        public func status(atPath path: String) -> LabMarkerStatus? {
            var info = stat()
            guard lstat(path, &info) == 0 else { return nil }
            return LabMarkerStatus(
                isRegularFile: info.st_mode & S_IFMT == S_IFREG,
                ownerUID: info.st_uid,
                permissions: UInt16(info.st_mode & 0o7777),
            )
        }

        /// The file's bytes when it is no larger than `limit`.
        public func contents(atPath path: String, limit: Int) -> Data? {
            guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
            defer { try? handle.close() }
            do {
                let data = try handle.read(upToCount: limit + 1) ?? Data()
                return data.count <= limit ? data : nil
            } catch {
                return nil
            }
        }
    }

#endif
