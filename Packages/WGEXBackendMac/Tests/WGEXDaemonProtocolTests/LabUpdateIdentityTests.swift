// SPDX-License-Identifier: MIT
#if os(macOS)
    import Darwin
    import Foundation
    import Security
    import Synchronization
    import Testing
    import WGEXCore
    @testable import WGEXDaemonProtocol

    /// DEC-013: the test bundle links every package module statically, so its image holds exactly what a build of
    /// this flavour compiles. Markers are joined at run time so this file does not supply them itself.
    private struct LabUpdateIdentityPresenceTests {
        @Test
        func `the Lab update identity is compiled into Lab builds only`() throws {
            var info = Dl_info()
            try #require(dladdr(#dsohandle, &info) != 0)
            let image = try Data(contentsOf: URL(fileURLWithPath: String(cString: info.dli_fname)), options: .mappedIfSafe)
            #if WGEX_LAB_BUILD
                let compiled = true
            #else
                let compiled = false
            #endif
            let markers = [
                ["wgex-lab-daemon", "-cdhash"], ["LabClient", "Admission"], ["LabDaemon", "IdentityFile"], ["LabDaemon", "Pin"],
                ["LabRunning", "Code"], ["installed", "Clients"],
            ].map { $0.joined() }
            for marker in markers {
                #expect((image.range(of: Data(marker.utf8)) != nil) == compiled, "\(marker)")
            }
        }
    }

    #if WGEX_LAB_BUILD
        /// A real temporary root; nothing under /Library, /var or a running daemon is touched.
        private final class TemporaryRoot: Sendable {
            private struct Unavailable: Error {}
            let url: URL

            init() throws {
                let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
                guard let canonical = realpath(base, nil) else { throw Unavailable() }
                defer { free(canonical) }
                url = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent("wgex-lab-identity-" + UUID().uuidString)
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
            }

            deinit { try? FileManager.default.removeItem(at: url) }

            var file: LabDaemonIdentityFile {
                LabDaemonIdentityFile(directory: url, ownerUID: geteuid())
            }

            var published: URL {
                url.appendingPathComponent(LabDaemonIdentityFile.name)
            }

            func plant(_ bytes: Data, mode: Int) throws {
                try? FileManager.default.removeItem(at: published)
                guard FileManager.default.createFile(atPath: published.path, contents: bytes, attributes: [.posixPermissions: mode]) else {
                    throw Unavailable()
                }
            }

            func mode(of url: URL) throws -> Int {
                guard let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int else {
                    throw Unavailable()
                }
                return mode
            }
        }

        /// Models SecCodeCheckValidity for a Lab requirement: a peer of one identifier and one cdhash satisfies it
        /// exactly when the requirement names that pair. The requirement must also parse as a real Security requirement.
        private struct SignedPeer {
            let identifier: String
            let cdhash: Data

            func satisfies(_ requirement: String) -> Bool {
                var parsed: SecRequirement?
                guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess else { return false }
                let hex = cdhash.map { String(format: "%02x", $0) }.joined()
                return requirement.contains("(identifier \"\(identifier)\" and cdhash H\"\(hex)\")")
            }
        }

        /// The installed binaries as the daemon would measure them now; replacing one models an update.
        private final class InstalledBinaries: CodeIdentityReading {
            private let hashes: Mutex<[String: [Data]]>
            private let reads = Mutex(0)

            init(_ hashes: [String: [Data]]) {
                self.hashes = Mutex(hashes)
            }

            var measurements: Int {
                reads.withLock { $0 }
            }

            func replace(_ path: String, with value: [Data]) {
                hashes.withLock { $0[path] = value }
            }

            func cdhashes(at url: URL) throws -> [Data] {
                reads.withLock { $0 += 1 }
                guard let result = hashes.withLock({ $0[url.path] }) else { throw DaemonFailure(code: .securityMissingHash) }
                return result
            }
        }

        private struct LabClientAdmissionTests {
            private static let app = "/Applications/WGEX.app/Contents/MacOS/WGEX"
            private static let cli = "/Applications/WGEX.app/Contents/Helpers/wgex"
            private let appHash = Data(repeating: 0xA1, count: 20)
            private let cliHash = Data(repeating: 0xC1, count: 20)
            private let otherHash = Data(repeating: 0x0E, count: 20)

            private final class Counter: Sendable {
                private let value = Mutex(0)
                var count: Int {
                    value.withLock { $0 }
                }

                func increment() {
                    value.withLock { $0 += 1 }
                }
            }

            private func admission(_ installed: InstalledBinaries, peer: SignedPeer, checks: Counter = Counter()) -> String? {
                LabClientAdmission(reader: installed, satisfies: { token, requirement in
                    checks.increment()
                    return token == Data([1]) && peer.satisfies(requirement)
                }).requirement(auditToken: Data([1]))
            }

            @Test
            func `a client matching the installed app or CLI is admitted under the requirement measured now`() throws {
                let installed = InstalledBinaries([Self.app: [appHash], Self.cli: [cliHash]])
                let expected = try RequirementStrings.lab(identifierHashes: [
                    (BuildIdentifiers.current.app, [appHash]), (BuildIdentifiers.current.cli, [cliHash]),
                ])
                #expect(admission(installed, peer: SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: appHash)) == expected)
                #expect(admission(installed, peer: SignedPeer(identifier: BuildIdentifiers.current.cli, cdhash: cliHash)) == expected)
            }

            @Test
            func `a client matching neither installed binary is refused`() {
                let installed = InstalledBinaries([Self.app: [appHash], Self.cli: [cliHash]])
                for peer in [
                    SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: otherHash),
                    SignedPeer(identifier: BuildIdentifiers.current.cli, cdhash: appHash),
                    SignedPeer(identifier: BuildIdentifiers.current.daemon, cdhash: appHash),
                    SignedPeer(identifier: "com.example.other", cdhash: cliHash),
                ] {
                    #expect(admission(installed, peer: peer) == nil, "\(peer.identifier)")
                }
            }

            @Test
            func `the installed binaries are measured for every connection, never cached from the first`() {
                let installed = InstalledBinaries([Self.app: [appHash], Self.cli: [cliHash]])
                let base = SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: appHash)
                let update = SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: otherHash)
                #expect(admission(installed, peer: base) != nil)
                #expect(admission(installed, peer: update) == nil)
                installed.replace(Self.app, with: [otherHash])
                #expect(admission(installed, peer: update) != nil)
                #expect(admission(installed, peer: base) == nil)
                #expect(installed.measurements == 8)
            }

            @Test
            func `nothing measurable at the fixed paths refuses without consulting the peer`() {
                let checks = Counter()
                let peer = SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: appHash)
                #expect(admission(InstalledBinaries([:]), peer: peer, checks: checks) == nil)
                #expect(admission(InstalledBinaries([Self.app: [], Self.cli: []]), peer: peer, checks: checks) == nil)
                #expect(checks.count == 0)
            }

            @Test
            func `the production check reads the audit token and fails closed`() throws {
                let installed = InstalledBinaries([Self.app: [appHash], Self.cli: [cliHash]])
                // No token, a malformed token, and this test process's own token (it is neither installed binary).
                var token = audit_token_t()
                var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
                let status = withUnsafeMutablePointer(to: &token) { pointer in
                    pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                        task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
                    }
                }
                try #require(status == KERN_SUCCESS)
                let own = withUnsafeBytes(of: token) { Data($0) }
                for candidate in [nil, Data([1, 2, 3]), own] {
                    #expect(LabClientAdmission(reader: installed).requirement(auditToken: candidate) == nil)
                }
            }
        }

        private struct LabDaemonIdentityFileTests {
            private let first = Data((0 ..< 20).map { UInt8($0) })
            private let second = Data(repeating: 0xFE, count: 20)

            @Test
            func `the published identity round-trips as a root-style 0644 file and pins the daemon identifier`() throws {
                let root = try TemporaryRoot()
                try root.file.publish([first, second, first])
                #expect(try root.file.read() == [first, second])
                #expect(try root.mode(of: root.published) == 0o644)
                let text = try String(contentsOf: root.published, encoding: .utf8)
                #expect(text == "000102030405060708090a0b0c0d0e0f10111213\n" + String(repeating: "fe", count: 20) + "\n")
                let requirement = try LabDaemonPin.requirement(file: root.file)
                #expect(try requirement == RequirementStrings.lab(identifierHashes: [(BuildIdentifiers.current.daemon, [first, second])]))
            }

            @Test
            func `the pinned daemon is accepted only when it matches the published hashes`() throws {
                let root = try TemporaryRoot()
                try root.file.publish([first])
                let requirement = try LabDaemonPin.requirement(file: root.file)
                #expect(SignedPeer(identifier: BuildIdentifiers.current.daemon, cdhash: first).satisfies(requirement))
                // A daemon other than the one that published, and a client binary with the published hash.
                #expect(!SignedPeer(identifier: BuildIdentifiers.current.daemon, cdhash: second).satisfies(requirement))
                #expect(!SignedPeer(identifier: BuildIdentifiers.current.app, cdhash: first).satisfies(requirement))
                try root.file.publish([second])
                #expect(try !SignedPeer(identifier: BuildIdentifiers.current.daemon, cdhash: first)
                    .satisfies(LabDaemonPin.requirement(file: root.file)))
            }

            @Test
            func `a missing file refuses`() throws {
                let root = try TemporaryRoot()
                #expect(throws: DaemonFailure(code: .securityLabMissingHash)) { try root.file.read() }
                #expect(throws: DaemonFailure(code: .securityLabMissingHash)) { try LabDaemonPin.requirement(file: root.file) }
            }

            @Test(arguments: [0o664, 0o646, 0o666, 0o744, 0o4644])
            func `a group- or world-writable or otherwise permissive file refuses`(_ mode: Int) throws {
                let root = try TemporaryRoot()
                try root.plant(LabDaemonIdentityFile.encode([first]), mode: 0o644)
                try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: root.published.path)
                #expect(throws: DaemonFailure.stateUnsafeMetadata) { try LabDaemonPin.requirement(file: root.file) }
            }

            @Test
            func `a stricter mode is accepted`() throws {
                let root = try TemporaryRoot()
                try root.plant(LabDaemonIdentityFile.encode([first]), mode: 0o600)
                #expect(try root.file.read() == [first])
            }

            @Test
            func `a symbolic link at the file or on the directory path refuses`() throws {
                let root = try TemporaryRoot()
                let target = root.url.appendingPathComponent("real")
                try #require(FileManager.default.createFile(
                    atPath: target.path, contents: LabDaemonIdentityFile.encode([first]), attributes: [.posixPermissions: 0o644],
                ))
                try FileManager.default.createSymbolicLink(at: root.published, withDestinationURL: target)
                #expect(throws: DaemonFailure.stateUnsafePath) { try LabDaemonPin.requirement(file: root.file) }

                let directory = root.url.appendingPathComponent("directory")
                try FileManager.default.createDirectory(
                    at: directory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o755],
                )
                try FileManager.default.copyItem(at: target, to: directory.appendingPathComponent(LabDaemonIdentityFile.name))
                let linked = root.url.appendingPathComponent("linked")
                try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: directory)
                #expect(try LabDaemonIdentityFile(directory: directory, ownerUID: geteuid()).read() == [first])
                #expect(throws: DaemonFailure.stateUnsafePath) {
                    try LabDaemonIdentityFile(directory: linked, ownerUID: geteuid()).read()
                }
            }

            @Test
            func `an oversized file refuses before parsing`() throws {
                let root = try TemporaryRoot()
                try root.plant(Data(repeating: UInt8(ascii: "a"), count: LabDaemonIdentityFile.maximumSize + 1), mode: 0o644)
                #expect(throws: DaemonFailure.stateTooLarge) { try root.file.read() }
            }

            @Test
            func `a hard link, a foreign owner or a writable directory refuses`() throws {
                let root = try TemporaryRoot()
                try root.file.publish([first])
                #expect(throws: DaemonFailure.stateUnsafeMetadata) {
                    try LabDaemonIdentityFile(directory: root.url, ownerUID: geteuid() + 1).read()
                }
                let alias = root.url.appendingPathComponent("alias")
                try FileManager.default.linkItem(at: root.published, to: alias)
                #expect(throws: DaemonFailure.stateUnsafeMetadata) { try root.file.read() }
                try FileManager.default.removeItem(at: alias)
                #expect(try root.file.read() == [first])
                try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: root.url.path)
                #expect(throws: DaemonFailure.stateUnsafeMetadata) { try root.file.read() }
                #expect(throws: DaemonFailure.stateUnsafeMetadata) { try root.file.publish([first]) }
            }

            @Test(arguments: [
                "", "\n", "000102030405060708090a0b0c0d0e0f10111213", "000102030405060708090A0B0C0D0E0F10111213\n",
                "000102030405060708090a0b0c0d0e0f1011121\n", "000102030405060708090a0b0c0d0e0f1011121314\n",
                "000102030405060708090a0b0c0d0e0f10111213\n\n", " 000102030405060708090a0b0c0d0e0f10111213\n",
                "000102030405060708090a0b0c0d0e0f1011121g\n", "000102030405060708090a0b0c0d0e0f10111213\r\n",
                String(repeating: "000102030405060708090a0b0c0d0e0f10111213\n", count: 9),
            ])
            func `malformed content refuses`(_ text: String) throws {
                let root = try TemporaryRoot()
                try root.plant(Data(text.utf8), mode: 0o644)
                #expect(throws: DaemonFailure(code: .securityLabInvalidHash)) { try LabDaemonPin.requirement(file: root.file) }
            }

            @Test
            func `publication refuses no hashes, a short hash or too many hashes`() throws {
                let root = try TemporaryRoot()
                #expect(throws: DaemonFailure(code: .securityLabMissingHash)) { try root.file.publish([]) }
                #expect(throws: DaemonFailure(code: .securityLabInvalidHash)) { try root.file.publish([Data(repeating: 1, count: 19)]) }
                let many = (0 ..< 9).map { Data(repeating: UInt8($0), count: 20) }
                #expect(throws: DaemonFailure(code: .securityLabInvalidHash)) { try root.file.publish(many) }
                #expect(try FileManager.default.contentsOfDirectory(atPath: root.url.path).isEmpty)
            }

            @Test
            func `publication replaces the old value atomically and never writes through a planted link`() throws {
                let root = try TemporaryRoot()
                try root.file.publish([first])
                try root.file.publish([second])
                #expect(try root.file.read() == [second])
                #expect(try FileManager.default.contentsOfDirectory(atPath: root.url.path) == [LabDaemonIdentityFile.name])

                let victim = root.url.appendingPathComponent("victim")
                try #require(FileManager.default.createFile(
                    atPath: victim.path,
                    contents: Data("keep".utf8),
                    attributes: [.posixPermissions: 0o644],
                ))
                try FileManager.default.removeItem(at: root.published)
                try FileManager.default.createSymbolicLink(at: root.published, withDestinationURL: victim)
                try root.file.publish([first])
                #expect(try Data(contentsOf: victim) == Data("keep".utf8))
                #expect(try root.file.read() == [first])
                #expect(try root.mode(of: root.published) == 0o644)
            }

            @Test
            func `the running-code reader refuses a process that is not the daemon`() {
                #expect(throws: DaemonFailure.self) { try LabRunningCode().runningCdhashes() }
            }

            @Test
            func `the Lab client opens no connection when the published identity is missing or unsafe`() async throws {
                let root = try TemporaryRoot()
                let transport = NSXPCClientTransport(labDaemonIdentity: root.file)
                await #expect(throws: DaemonFailure(code: .securityLabMissingHash)) { try await transport.connect(callbacks: .init()) }
                await #expect(throws: DaemonError.disconnected) { try await transport.send(Envelope(body: .status).encoded(), secrets: nil)
                }
                try root.plant(LabDaemonIdentityFile.encode([first]), mode: 0o666)
                await #expect(throws: DaemonFailure.stateUnsafeMetadata) { try await transport.connect(callbacks: .init()) }
                await #expect(throws: DaemonError.disconnected) { try await transport.send(Envelope(body: .status).encoded(), secrets: nil)
                }
                await transport.invalidate()
            }
        }
    #endif
#endif
