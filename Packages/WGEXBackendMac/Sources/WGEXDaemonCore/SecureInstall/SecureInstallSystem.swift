// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

/// Metadata comes from lstat, including symlinks themselves, never their targets.
public struct SecureInstallEntry: Sendable, Hashable {
    public enum Kind: Sendable { case directory, file, symlink }
    public var relativePath: String
    public var uid: UInt32
    public var gid: UInt32
    public var mode: UInt16
    public var device: UInt64 = 0
    public var inode: UInt64 = 0
    public var changeStamp: String = ""
    public var kind: Kind
    /// Conservative effective-write check: any mutating ACL allow entry is unsafe.
    public var aclWritable = false
    /// Bundle entries permit no ACL, including non-mutating entries.
    public var hasACL = false
    /// Ancestors may grant mutation only to root or known admin principals.
    public var aclAdminOnly = false

    /// Evaluates the shared ancestor policy without relaxing bundle entry permissions.
    public var ancestorWritable: Bool {
        uid != 0 || mode & 0o002 != 0 || (mode & 0o020 != 0 && gid != 80) || (aclWritable && !aclAdminOnly)
    }

    public init(relativePath: String, uid: UInt32, gid: UInt32, mode: UInt16, kind: Kind = .file) {
        self.relativePath = relativePath; self.uid = uid; self.gid = gid; self.mode = mode; self.kind = kind
    }

    public var nonRootWritable: Bool {
        if kind == .symlink {
            return uid != 0
        }
        return aclWritable || mode & 0o022 != 0 || (uid != 0 && mode & 0o200 != 0)
    }

    /// Preserve which regular files are executable, while making the installed bundle readable.
    package var installedMode: UInt16 {
        kind == .directory || mode & 0o111 != 0 ? 0o755 : 0o644
    }
}

/// Every filesystem and signing operation is injectable. Paths are relative to an anchored bundle descriptor.
public protocol SecureInstallSystem: Sendable {
    func daemonExecutablePath() throws -> String
    func entries(bundlePath: String) throws -> [SecureInstallEntry]
    /// Includes /Applications, which must not permit replacing the bundle.
    func ancestors(bundlePath: String) throws -> [SecureInstallEntry]
    /// Strips ACLs and unsafe mode bits before changing ownership, on a single no-follow descriptor.
    func repair(_ entry: SecureInstallEntry, bundlePath: String) throws
    func chown(_ entry: SecureInstallEntry, bundlePath: String, uid: UInt32, gid: UInt32) throws
    func chmod(_ entry: SecureInstallEntry, bundlePath: String, mode: UInt16) throws
    func checkIdentity(bundlePath: String, daemonPath: String) throws -> SecureInstallIdentity
}

public struct SecureInstallIdentity: Sendable {
    public var bundle: SecureInstallReport.IdentityCheck
    public var daemon: SecureInstallReport.IdentityCheck
    public init(bundle: SecureInstallReport.IdentityCheck, daemon: SecureInstallReport.IdentityCheck) {
        self.bundle = bundle; self.daemon = daemon
    }
}

public protocol SecureInstallChecking: Sendable {
    func status() async -> SecureInstallReport
    func perform() async -> SecureInstallReport
    /// Invalidates cached noninteractive key validation after installation changes.
    func invalidate() async
}

public extension SecureInstallChecking {
    func invalidate() async {}
}

/// Fail closed when a composition has not supplied the guarded adapter.
public struct UnavailableSecureInstall: SecureInstallChecking {
    public init() {}
    public func status() async -> SecureInstallReport {
        SecureInstallReport(state: .needsAttention(.inspectionFailed), bundlePath: "", isUnderApplications: false)
    }

    public func perform() async -> SecureInstallReport {
        await status()
    }
}
