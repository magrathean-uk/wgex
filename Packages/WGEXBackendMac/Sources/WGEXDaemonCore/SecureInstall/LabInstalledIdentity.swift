// SPDX-License-Identifier: MIT
// DEC-013: Lab-only secure-install identity. Lab builds have no stable certificate (DEC-007), so a Lab requirement
// names code-directory hashes. Pinning them at daemon start would make a running daemon refuse a compatible update
// installed under it (M5.3-07: its five-second tick checks the replaced bundle). Nothing here is compiled outside
// WGEX_LAB_BUILD; Release keeps its fixed requirement strings.
#if os(macOS) && WGEX_LAB_BUILD
    import Foundation
    import WGEXCore
    import WGEXDaemonProtocol

    /// Measures the installed app and daemon at each identity check, the way the Lab listener measures each
    /// connecting client, and checks each against the requirement built from that measurement. Nothing is cached:
    /// a binary that cannot be measured, or that changes between measurement and check, fails with no fallback.
    package struct LabInstalledIdentity: Sendable {
        /// Checks the code at a path against a requirement string (production: strict static validation).
        package typealias Check = @Sendable (_ path: String, _ requirement: String) -> SecureInstallReport.IdentityCheck

        /// The app's main executable inside the bundle.
        package static let appExecutable = "Contents/MacOS/WGEX"

        private let reader: any CodeIdentityReading
        private let appIdentifier: String
        private let daemonIdentifier: String
        private let check: Check

        package init(
            reader: any CodeIdentityReading = CodeIdentity(),
            appIdentifier: String = BuildIdentifiers.current.app,
            daemonIdentifier: String = BuildIdentifiers.current.daemon,
            check: @escaping Check,
        ) {
            self.reader = reader
            self.appIdentifier = appIdentifier
            self.daemonIdentifier = daemonIdentifier
            self.check = check
        }

        /// The bundle and the daemon executable, each checked against what is installed at this moment.
        package func identity(bundlePath: String, daemonPath: String) -> SecureInstallIdentity {
            SecureInstallIdentity(
                bundle: verify(path: bundlePath, identifier: appIdentifier, measuring: bundlePath + "/" + Self.appExecutable),
                daemon: verify(path: daemonPath, identifier: daemonIdentifier, measuring: daemonPath),
            )
        }

        private func verify(path: String, identifier: String, measuring executable: String) -> SecureInstallReport.IdentityCheck {
            guard let requirement = try? RequirementStrings.lab(identifierHashes: [(
                identifier, reader.cdhashes(at: URL(fileURLWithPath: executable)),
            )]) else { return .failed }
            return check(path, requirement)
        }
    }
#endif
