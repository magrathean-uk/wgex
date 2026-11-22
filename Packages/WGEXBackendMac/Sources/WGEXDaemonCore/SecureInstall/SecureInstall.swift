// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

/// Serialises inspection and repair; no child process or shell is involved.
public actor SecureInstall: SecureInstallChecking {
    private let system: any SecureInstallSystem
    private let bundlePath: String
    private let provisionKey: @Sendable () throws -> Void
    private let validateKey: @Sendable () throws -> Void
    private var keyRepairFailed = false
    private var keyValidated: Bool?
    private var identityCache: (entries: [SecureInstallEntry], identity: SecureInstallIdentity)?

    /// Separates bundle repair, missing-key provisioning and noninteractive key validation.
    public init(
        system: any SecureInstallSystem,
        bundlePath: String = "/Applications/WGEX.app",
        provisionKey: @escaping @Sendable () throws -> Void = {},
        validateKey: @escaping @Sendable () throws -> Void = {},
    ) {
        self.system = system; self.bundlePath = bundlePath; self.provisionKey = provisionKey; self.validateKey = validateKey
    }

    /// Walk metadata on every call. Root directory mtime alone misses nested chmod and replacement.
    public func status() -> SecureInstallReport {
        var report = inspect().report
        if report.state == .verified {
            if keyRepairFailed {
                report.state = .needsAttention(.wrappingKeyRepairFailed); return report
            }
            if keyValidated == nil {
                do { try validateKey(); keyValidated = true }
                catch { keyValidated = false }
            }
            if keyValidated != true {
                report.state = .needsAttention(.wrappingKeyUnavailable)
            }
        }
        return report
    }

    /// Explicit installation changes invalidate the bounded boot validation result.
    public func invalidate() async {
        keyValidated = nil; keyRepairFailed = false
    }

    public func perform() -> SecureInstallReport {
        keyValidated = nil
        let before = inspect()
        // Structural inspection failures return no entries; incorrect modes remain repairable.
        guard before.report.isUnderApplications, before.report.bundleIdentity == .matched,
              before.report.daemonIdentity == .matched,
              !before.entries.isEmpty
        else { return before.report }
        do {
            // Never promote a user-owned setuid/setgid bit into a root executable.
            // Children first preserves access until the entire subtree has been repaired.
            for entry in before.entries.reversed() {
                try system.repair(entry, bundlePath: bundlePath)
            }
            identityCache = nil
            var report = inspect().report
            if report.state == .verified {
                do {
                    try provisionKey()
                    try validateKey()
                    keyValidated = true; keyRepairFailed = false
                    report = inspect().report
                } catch {
                    keyRepairFailed = (error as? DaemonFailure) == .keyAccessRepairFailed
                    report.state = .needsAttention(keyRepairFailed ? .wrappingKeyRepairFailed : .wrappingKeyUnavailable)
                }
            }
            return report
        } catch {
            var report = inspect().report
            report.state = .needsAttention(.inspectionFailed)
            return report
        }
    }

    private func inspect() -> (report: SecureInstallReport, entries: [SecureInstallEntry]) {
        let canonical = URL(fileURLWithPath: bundlePath).standardizedFileURL.path
        let inApplications = canonical.hasPrefix("/Applications/") && canonical.hasSuffix(".app") && canonical == bundlePath
        var report = SecureInstallReport(
            state: .needsAttention(.inspectionFailed), bundlePath: bundlePath, isUnderApplications: inApplications,
        )
        guard inApplications else { report.state = .needsAttention(.notInApplications); return (report, []) }
        do {
            let executable = try system.daemonExecutablePath()
            let ownRoot = try BundleLayout.root(ofExecutable: URL(fileURLWithPath: executable)).path
            guard ownRoot == canonical, executable == canonical + "/Contents/MacOS/WGEXDaemon" else {
                report.state = .needsAttention(.wrongBundle); return (report, [])
            }
            let entries = try system.entries(bundlePath: canonical)
            let ancestors = try system.ancestors(bundlePath: canonical)
            guard entries.contains(where: { $0.relativePath == "." && $0.kind == .directory }),
                  entries.contains(where: { $0.relativePath == "Contents/MacOS/WGEXDaemon" && $0.kind == .file }),
                  entries.allSatisfy({ Self.validRelativePath($0.relativePath) }) else { return (report, []) }
            report.nonRootOwnedEntries = entries.count { $0.uid != 0 || $0.gid != 0 } + ancestors.count { $0.uid != 0 }
            report.nonRootWritableEntries = entries.count { $0.nonRootWritable } + ancestors.count { $0.ancestorWritable }
            let identity: SecureInstallIdentity
            if let cached = identityCache, cached.entries == entries {
                identity = cached.identity
            } else {
                identity = try system.checkIdentity(bundlePath: canonical, daemonPath: executable)
                identityCache = (entries, identity)
            }
            report.bundleIdentity = identity.bundle; report.daemonIdentity = identity.daemon
            if identity.bundle != .matched || identity.daemon != .matched {
                report.state = .needsAttention(.identityMismatch)
            } else if entries.contains(where: { $0.hasACL || $0.aclWritable }) || ancestors
                .contains(where: { $0.aclWritable && !$0.aclAdminOnly })
            {
                report.state = .needsAttention(.aclWritable)
            } else if report.nonRootWritableEntries > 0 {
                report.state = .needsAttention(.bundleWritable)
            } else if report.nonRootOwnedEntries > 0 {
                report.state = .needsAttention(.notRootOwned)
            } else if entries.contains(where: { $0.kind != .symlink && $0.mode & 0o7777 != $0.installedMode }) {
                report.state = .needsAttention(.inspectionFailed)
            } else {
                report.state = .verified
            }
            return (report, entries)
        } catch { return (report, []) }
    }

    package static func validRelativePath(_ path: String) -> Bool {
        path == "." || (!path.isEmpty && !path.hasPrefix("/") && path.split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." })
    }
}
