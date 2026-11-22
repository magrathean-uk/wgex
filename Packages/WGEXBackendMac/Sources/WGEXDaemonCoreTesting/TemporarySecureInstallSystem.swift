// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonCore
import WGEXDaemonProtocol

/// Reads only an existing temporary bundle. Repairs and identity checks are supplied by a fake.
/// No temporary directory may select the production bundle or perform ownership/mode changes.
package struct TemporarySecureInstallSystem: SecureInstallSystem {
    private let root: URL
    package init(root: URL) throws {
        let temporary = try SecureBundleDescriptor.canonicalPath(FileManager.default.temporaryDirectory.path) + "/"
        let canonical = try URL(fileURLWithPath: SecureBundleDescriptor.canonicalPath(root.path))
        guard canonical.path.hasPrefix(temporary), canonical.path != temporary else { throw DaemonFailure.hostSystem(EINVAL) }
        self.root = canonical
    }

    package func daemonExecutablePath() -> String {
        root.path + "/Contents/MacOS/WGEXDaemon"
    }

    package func entries(bundlePath: String) throws -> [SecureInstallEntry] {
        guard bundlePath == root.path else { throw DaemonFailure.hostSystem(EINVAL) }
        let bundle = try SecureBundleDescriptor(path: bundlePath)
        defer { close(bundle.descriptor) }
        return try bundle.entries()
    }

    package func ancestors(bundlePath _: String) -> [SecureInstallEntry] {
        []
    }

    package func repair(_: SecureInstallEntry, bundlePath _: String) throws {
        throw DaemonFailure.hostSystem(EPERM)
    }

    package func chown(_: SecureInstallEntry, bundlePath _: String, uid _: UInt32, gid _: UInt32) throws {
        throw DaemonFailure.hostSystem(EPERM)
    }

    package func chmod(_: SecureInstallEntry, bundlePath _: String, mode _: UInt16) throws {
        throw DaemonFailure.hostSystem(EPERM)
    }

    package func checkIdentity(bundlePath _: String, daemonPath _: String) -> SecureInstallIdentity {
        SecureInstallIdentity(bundle: .unavailable, daemon: .unavailable)
    }
}
