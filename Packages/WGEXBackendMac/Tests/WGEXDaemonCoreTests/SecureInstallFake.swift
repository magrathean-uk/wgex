// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

package struct VerifiedSecureInstall: SecureInstallChecking {
    package func status() -> SecureInstallReport {
        SecureInstallReport(
            state: .verified,
            bundlePath: "/Applications/WGEX.app",
            isUnderApplications: true,
            bundleIdentity: .matched,
            daemonIdentity: .matched,
        )
    }

    package func perform() -> SecureInstallReport {
        status()
    }
}

package final class FakeSecureInstallSystem: SecureInstallSystem {
    package struct State {
        package var entries: [SecureInstallEntry] = [
            .init(relativePath: ".", uid: 0, gid: 0, mode: 0o755, kind: .directory),
            .init(relativePath: "Contents/MacOS/WGEXDaemon", uid: 0, gid: 0, mode: 0o755),
        ]
        package var ancestors: [SecureInstallEntry] = []
        package var executable = "/Applications/WGEX.app/Contents/MacOS/WGEXDaemon"
        package var identity = SecureInstallIdentity(bundle: .matched, daemon: .matched)
        package var ownershipCalls: [String] = []
        package var modeCalls: [(String, UInt16)] = []
        package var identityChecks = 0
        package var failRepair = false
        package var skipModeRepair = false
    }

    package let state = Mutex(State())
    package func daemonExecutablePath() -> String {
        state.withLock { $0.executable }
    }

    package func entries(bundlePath _: String) -> [SecureInstallEntry] {
        state.withLock { $0.entries }
    }

    package func ancestors(bundlePath _: String) -> [SecureInstallEntry] {
        state.withLock { $0.ancestors }
    }

    package func repair(_ entry: SecureInstallEntry, bundlePath: String) throws {
        if entry.kind != .symlink, !state.withLock({ $0.skipModeRepair }) {
            chmod(entry, bundlePath: bundlePath, mode: entry.installedMode)
        }
        try chown(entry, bundlePath: bundlePath, uid: 0, gid: 0)
        state.withLock { value in
            for index in value.entries.indices where value.entries[index].relativePath == entry.relativePath {
                value.entries[index].aclWritable = false
                value.entries[index].hasACL = false
            }
        }
    }

    package func chown(_ entry: SecureInstallEntry, bundlePath _: String, uid: UInt32, gid: UInt32) throws {
        try state.withLock { value in
            if value.failRepair {
                throw HostTestError.injected
            }
            value.ownershipCalls.append(entry.relativePath)
            for index in value.entries.indices where value.entries[index].relativePath == entry.relativePath {
                value.entries[index].uid = uid; value.entries[index].gid = gid
            }
        }
    }

    package func chmod(_ entry: SecureInstallEntry, bundlePath _: String, mode: UInt16) {
        state.withLock { value in
            value.modeCalls.append((entry.relativePath, mode))
            for index in value.entries.indices where value.entries[index].relativePath == entry.relativePath {
                value.entries[index].mode = mode
            }
        }
    }

    package func checkIdentity(bundlePath _: String, daemonPath _: String) -> SecureInstallIdentity {
        state.withLock { $0.identityChecks += 1; return $0.identity }
    }
}
