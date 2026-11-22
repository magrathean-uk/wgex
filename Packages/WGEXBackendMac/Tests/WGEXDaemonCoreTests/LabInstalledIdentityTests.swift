// SPDX-License-Identifier: MIT
#if os(macOS) && WGEX_LAB_BUILD
    import Foundation
    import Synchronization
    import Testing
    @testable import WGEXDaemonCore
    import WGEXDaemonProtocol

    /// One installed binary as signing sees it.
    private struct InstalledCode: Equatable {
        var identifier: String
        var hash: Data
    }

    /// The fake disk: what the check sees, what the reader measures, and every requirement checked.
    private struct InstalledFiles {
        var checked: [String: InstalledCode] = [:]
        var measured: [String: InstalledCode]?
        var unmeasurable: Set<String> = []
        var requirements: [(path: String, requirement: String)] = []
    }

    /// DEC-013, M5.3-07: Lab secure install measures the installed app and daemon at each identity check. The running
    /// daemon's tick re-checks the bundle once its entries change, so after an update is installed under it the check
    /// must name the update, not hashes captured at daemon start. Fakes stand in for signing; no host file is read.
    private struct LabInstalledIdentityTests {
        private static let bundle = "/Applications/WGEX.app"
        private static let app = bundle + "/" + LabInstalledIdentity.appExecutable
        private static let daemon = bundle + "/Contents/MacOS/WGEXDaemon"

        /// The installed files: identifier and code-directory hash per path, as the check sees them and as the reader
        /// measures them. `measured` differs from `checked` only to model a swap between the two.
        private final class Disk: CodeIdentityReading, Sendable {
            let state = Mutex(InstalledFiles())

            init(app: InstalledCode, daemon: InstalledCode) {
                install(app: app, daemon: daemon)
            }

            func install(app: InstalledCode, daemon: InstalledCode) {
                state.withLock { $0.checked = [LabInstalledIdentityTests.bundle: app, LabInstalledIdentityTests.daemon: daemon] }
            }

            func cdhashes(at executableURL: URL) throws -> [Data] {
                try state.withLock { value in
                    let path = executableURL.path
                    guard !value.unmeasurable.contains(path) else { throw HostTestError.injected }
                    // The app is measured at its main executable and checked at its bundle.
                    let key = path == LabInstalledIdentityTests.app ? LabInstalledIdentityTests.bundle : path
                    return [(value.measured ?? value.checked)[key]?.hash].compactMap(\.self)
                }
            }

            /// Models strict static validation: the code at `path` must satisfy one `identifier ... and cdhash ...` clause.
            func check(path: String, requirement: String) -> SecureInstallReport.IdentityCheck {
                state.withLock { value in
                    value.requirements.append((path, requirement))
                    guard let code = value.checked[path] else { return .failed }
                    let clause = "(identifier \"\(code.identifier)\" and cdhash H\"\(Self.hex(code.hash))\")"
                    return requirement.components(separatedBy: " or ").contains(clause) ? .matched : .failed
                }
            }

            static func hex(_ hash: Data) -> String {
                hash.map { String(format: "%02x", $0) }.joined()
            }
        }

        private static func hash(_ byte: UInt8) -> Data {
            Data(repeating: byte, count: 20)
        }

        private static let base = (
            app: InstalledCode(identifier: "test.app", hash: hash(0xA1)),
            daemon: InstalledCode(identifier: "test.daemon", hash: hash(0xD1)),
        )
        private static let update = (
            app: InstalledCode(identifier: "test.app", hash: hash(0xA2)),
            daemon: InstalledCode(identifier: "test.daemon", hash: hash(0xD2)),
        )

        private static func identity(_ disk: Disk) -> LabInstalledIdentity {
            LabInstalledIdentity(reader: disk, appIdentifier: "test.app", daemonIdentifier: "test.daemon") { path, requirement in
                disk.check(path: path, requirement: requirement)
            }
        }

        /// The daemon's secure-install system: the fake bundle walk, with the Lab identity check under test.
        private struct LabSystem: SecureInstallSystem {
            let walk = FakeSecureInstallSystem()
            let identity: LabInstalledIdentity

            func daemonExecutablePath() -> String {
                walk.daemonExecutablePath()
            }

            func entries(bundlePath: String) -> [SecureInstallEntry] {
                walk.entries(bundlePath: bundlePath)
            }

            func ancestors(bundlePath: String) -> [SecureInstallEntry] {
                walk.ancestors(bundlePath: bundlePath)
            }

            func repair(_ entry: SecureInstallEntry, bundlePath: String) throws {
                try walk.repair(entry, bundlePath: bundlePath)
            }

            func chown(_ entry: SecureInstallEntry, bundlePath: String, uid: UInt32, gid: UInt32) throws {
                try walk.chown(entry, bundlePath: bundlePath, uid: uid, gid: gid)
            }

            func chmod(_ entry: SecureInstallEntry, bundlePath: String, mode: UInt16) {
                walk.chmod(entry, bundlePath: bundlePath, mode: mode)
            }

            func checkIdentity(bundlePath: String, daemonPath: String) -> SecureInstallIdentity {
                identity.identity(bundlePath: bundlePath, daemonPath: daemonPath)
            }

            /// A bundle replaced by copy: every entry gets a new inode, so the identity cache cannot answer.
            func replaceBundle() {
                walk.state.withLock { value in
                    for index in value.entries.indices {
                        value.entries[index].inode += 1000
                    }
                }
            }
        }

        @Test
        func `an update installed under the running daemon is checked against the bundle installed now`() async {
            let disk = Disk(app: Self.base.app, daemon: Self.base.daemon)
            // Built once, as SystemSecureInstall does at daemon start.
            let system = LabSystem(identity: Self.identity(disk))
            let installer = SecureInstall(system: system)
            #expect(await installer.status().state == .verified)

            // M5.3-07: the update replaces /Applications/WGEX.app while the base daemon keeps running.
            disk.install(app: Self.update.app, daemon: Self.update.daemon)
            system.replaceBundle()
            let report = await installer.status()
            #expect(report.state == .verified)
            #expect(report.bundleIdentity == .matched && report.daemonIdentity == .matched)
            let latest = disk.state.withLock { Array($0.requirements.suffix(2)) }
            #expect(latest.map(\.path) == [Self.bundle, Self.daemon])
            #expect(latest[0].requirement.contains(Disk.hex(Self.update.app.hash)))
            #expect(latest[1].requirement.contains(Disk.hex(Self.update.daemon.hash)))
            let pinned = [Self.base.app.hash, Self.base.daemon.hash].map(Disk.hex)
            #expect(!latest.contains { entry in pinned.contains { entry.requirement.contains($0) } })
        }

        @Test
        func `a requirement captured at daemon start refuses that update`() throws {
            // The behaviour this replaces: the base build's hashes, pinned at start, refuse the installed update.
            let disk = Disk(app: Self.update.app, daemon: Self.update.daemon)
            let pinned = try RequirementStrings.lab(identifierHashes: [("test.app", [Self.base.app.hash])])
            #expect(disk.check(path: Self.bundle, requirement: pinned) == .failed)
            #expect(Self.identity(disk).identity(bundlePath: Self.bundle, daemonPath: Self.daemon).bundle == .matched)
        }

        @Test
        func `an installed app or daemon with another identifier is refused`() async {
            let foreignApp = Disk(app: .init(identifier: "other.app", hash: Self.hash(0xA1)), daemon: Self.base.daemon)
            let appReport = await SecureInstall(system: LabSystem(identity: Self.identity(foreignApp))).status()
            #expect(appReport.state == .needsAttention(.identityMismatch))
            #expect(appReport.bundleIdentity == .failed && appReport.daemonIdentity == .matched)

            let foreignDaemon = Disk(app: Self.base.app, daemon: .init(identifier: "other.daemon", hash: Self.hash(0xD1)))
            let daemonReport = await SecureInstall(system: LabSystem(identity: Self.identity(foreignDaemon))).status()
            #expect(daemonReport.state == .needsAttention(.identityMismatch))
            #expect(daemonReport.bundleIdentity == .matched && daemonReport.daemonIdentity == .failed)
        }

        @Test
        func `nothing measurable at a fixed path fails with no fallback`() {
            let disk = Disk(app: Self.base.app, daemon: Self.base.daemon)
            let identity = Self.identity(disk)
            disk.state.withLock { $0.unmeasurable = [Self.app] }
            let unreadable = identity.identity(bundlePath: Self.bundle, daemonPath: Self.daemon)
            #expect(unreadable.bundle == .failed && unreadable.daemon == .matched)
            // The check never ran for the bundle: there was no requirement to check it against.
            #expect(disk.state.withLock { $0.requirements.map(\.path) } == [Self.daemon])

            disk.state.withLock { $0.unmeasurable = []; $0.measured = [Self.bundle: Self.base.app] }
            let unsigned = identity.identity(bundlePath: Self.bundle, daemonPath: Self.daemon)
            #expect(unsigned.bundle == .matched && unsigned.daemon == .failed)
        }

        @Test
        func `a binary swapped between measurement and check is refused`() {
            let disk = Disk(app: Self.update.app, daemon: Self.update.daemon)
            disk.state.withLock { $0.measured = [Self.bundle: Self.base.app, Self.daemon: Self.base.daemon] }
            let identity = Self.identity(disk).identity(bundlePath: Self.bundle, daemonPath: Self.daemon)
            #expect(identity.bundle == .failed && identity.daemon == .failed)
        }
    }
#endif
