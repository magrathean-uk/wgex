// SPDX-License-Identifier: MIT
// DEC-013: Lab-only update identity, so an update hand-off can run between two ad hoc Lab builds. Nothing in this
// file is compiled outside WGEX_LAB_BUILD; Release requirement strings and pinning never reach these paths.
#if os(macOS) && WGEX_LAB_BUILD
    import Darwin
    import Foundation
    import os
    import Security
    import WGEXCore

    /// Daemon side: admits a connecting client only when the code behind its kernel audit token matches the app or
    /// the CLI installed at their fixed paths, measured for this connection, never a value captured at daemon start.
    package struct LabClientAdmission: Sendable {
        /// The fixed install location of the app bundle, the same path secure install checks.
        package static let installedBundle = URL(fileURLWithPath: "/Applications/WGEX.app")
        private static let logger = Logger(subsystem: BuildIdentifiers.current.logSubsystem, category: "lab-code-identity")

        private let bundle: URL
        private let reader: any CodeIdentityReading
        private let satisfies: @Sendable (Data?, String) -> Bool

        /// `satisfies` checks the audit token's code against a requirement; production uses the daemon's audit-token
        /// identity check, which fails closed on a missing or malformed token.
        package init(
            bundle: URL = installedBundle,
            reader: any CodeIdentityReading = CodeIdentity(),
            satisfies: @escaping @Sendable (Data?, String) -> Bool = { token, requirement in
                DaemonAuthorisation.isAppProcess(auditToken: token, requirement: requirement)
            },
        ) {
            self.bundle = bundle
            self.reader = reader
            self.satisfies = satisfies
        }

        /// The requirement measured now from the installed app and CLI when the peer satisfies it, otherwise nil.
        package func requirement(auditToken: Data?) -> String? {
            let requirement = LabPeerRequirements.installedClients(bundle: bundle, reader: reader)
            guard requirement != RequirementStrings.labDenyAll, satisfies(auditToken, requirement) else {
                Self.logger.error("Lab XPC client refused: its code matches neither the installed app nor the installed CLI")
                return nil
            }
            return requirement
        }
    }

    /// Client side: the running daemon's own code-directory hashes, published by the root daemon at startup and
    /// pinned by the Lab app and CLI instead of the hash of their own bundle's daemon.
    ///
    /// The file is one lowercase hex hash per line. It sits beside the Lab host marker (`/var/db/wgex-lab-host`),
    /// because the daemon's state directory is mode 0700 and a client running as the console user cannot traverse
    /// it. The canonical `/private/var/db` is used because `/var` is a symbolic link and no component may be one.
    /// Writer and reader apply the state-file checks: no symbolic link on the path, a containing directory owned by
    /// the expected owner and not writable by group or others, and a regular file with one link, that owner, mode
    /// 0644 or stricter and a bounded size.
    package struct LabDaemonIdentityFile: Sendable {
        /// The published location on a Lab guest, owned by root.
        package static let production = LabDaemonIdentityFile(directory: URL(fileURLWithPath: "/private/var/db"), ownerUID: 0)
        /// File name inside ``directory``.
        package static let name = "wgex-lab-daemon-cdhash"
        /// At most this many hashes, each 40 hex digits and a newline.
        package static let maximumHashes = 8
        /// Size bound applied before parsing.
        package static let maximumSize = 512

        package let directory: URL
        package let ownerUID: uid_t

        package init(directory: URL, ownerUID: uid_t) {
            self.directory = directory
            self.ownerUID = ownerUID
        }

        /// Replaces the file atomically: a new exclusive file, mode 0644, synchronised, then renamed over the old one.
        package func publish(_ hashes: [Data]) throws {
            let bytes = try Self.encode(hashes)
            let parent = try openDirectory()
            defer { close(parent) }
            let temporary = "." + Self.name + "." + UUID().uuidString
            let file = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
            guard file >= 0 else { throw DaemonFailure.stateUnsafePath }
            var renamed = false
            defer {
                close(file)
                if !renamed {
                    unlinkat(parent, temporary, 0)
                }
            }
            // The umask must not narrow what the console user's client needs to read.
            guard fchmod(file, 0o644) == 0 else { throw DaemonFailure.stateSystem(errno) }
            try check(file: file)
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(file, buffer.baseAddress?.advanced(by: offset), buffer.count - offset)
                    if count < 0, errno == EINTR {
                        continue
                    }
                    guard count > 0 else { throw DaemonFailure.stateSystem(errno) }
                    offset += count
                }
            }
            guard fsync(file) == 0, renameat(parent, temporary, parent, Self.name) == 0 else { throw DaemonFailure.stateSystem(errno) }
            renamed = true
            guard fsync(parent) == 0 else { throw DaemonFailure.stateSystem(errno) }
        }

        /// The published hashes. A missing file throws `securityLabMissingHash`; a link, a foreign owner, a permissive
        /// mode or an oversized file throws a state-file failure; malformed content throws `securityLabInvalidHash`.
        package func read() throws -> [Data] {
            let parent = try openDirectory()
            defer { close(parent) }
            let file = openat(parent, Self.name, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
            guard file >= 0 else {
                switch errno {
                case ENOENT: throw DaemonFailure(code: .securityLabMissingHash)
                case ELOOP: throw DaemonFailure.stateUnsafePath
                case EACCES: throw DaemonFailure.stateUnsafeMetadata
                default: throw DaemonFailure.stateSystem(errno)
                }
            }
            defer { close(file) }
            try check(file: file)
            var result = Data()
            var buffer = [UInt8](repeating: 0, count: Self.maximumSize + 1)
            while true {
                let count = Darwin.read(file, &buffer, buffer.count)
                if count < 0, errno == EINTR {
                    continue
                }
                guard count >= 0 else { throw DaemonFailure.stateSystem(errno) }
                if count == 0 {
                    return try Self.decode(result)
                }
                guard result.count + count <= Self.maximumSize else { throw DaemonFailure.stateTooLarge }
                result.append(contentsOf: buffer.prefix(count))
            }
        }

        /// Lowercase hex, one 20-byte hash per line, duplicates removed; empty or oversized lists are refused.
        package static func encode(_ hashes: [Data]) throws -> Data {
            let unique = hashes.reduce(into: [Data]()) {
                if !$0.contains($1) {
                    $0.append($1)
                }
            }
            guard !unique.isEmpty else { throw DaemonFailure(code: .securityLabMissingHash) }
            guard unique.count <= maximumHashes, unique.allSatisfy({ $0.count == 20 }) else {
                throw DaemonFailure(code: .securityLabInvalidHash)
            }
            return Data(unique.map { $0.map { String(format: "%02x", $0) }.joined() + "\n" }.joined().utf8)
        }

        /// Accepts only what ``encode(_:)`` writes: 1 to ``maximumHashes`` lines of 40 lowercase hex digits, each
        /// ending in a newline.
        package static func decode(_ bytes: Data) throws -> [Data] {
            let invalid = DaemonFailure(code: .securityLabInvalidHash)
            guard bytes.count <= maximumSize, bytes.last == UInt8(ascii: "\n") else { throw invalid }
            let lines = bytes.dropLast().split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: false)
            guard (1 ... maximumHashes).contains(lines.count) else { throw invalid }
            var hashes: [Data] = []
            for line in lines {
                guard line.count == 40 else { throw invalid }
                var hash = Data()
                var index = line.startIndex
                while index < line.endIndex {
                    guard let high = hexValue(line[index]), let low = hexValue(line[index + 1]) else { throw invalid }
                    hash.append(high << 4 | low)
                    index += 2
                }
                if !hashes.contains(hash) {
                    hashes.append(hash)
                }
            }
            return hashes
        }

        private static func hexValue(_ byte: UInt8) -> UInt8? {
            switch byte {
            case UInt8(ascii: "0") ... UInt8(ascii: "9"): byte - UInt8(ascii: "0")
            case UInt8(ascii: "a") ... UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
            default: nil
            }
        }

        /// Walks every component from the root without following links, then checks the containing directory.
        private func openDirectory() throws -> Int32 {
            let path = directory.path
            let components = path.split(separator: "/").map(String.init)
            guard path.hasPrefix("/"), !components.contains(".."), !components.contains(".") else {
                throw DaemonFailure.stateUnsafePath
            }
            var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard current >= 0 else { throw DaemonFailure.stateSystem(errno) }
            for component in components {
                let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                close(current)
                guard next >= 0 else { throw DaemonFailure.stateUnsafePath }
                current = next
            }
            var info = stat()
            guard fstat(current, &info) == 0 else {
                let status = errno
                close(current)
                throw DaemonFailure.stateSystem(status)
            }
            guard info.st_uid == ownerUID, info.st_mode & S_IFMT == S_IFDIR, info.st_mode & 0o022 == 0 else {
                close(current)
                throw DaemonFailure.stateUnsafeMetadata
            }
            return current
        }

        private func check(file: Int32) throws {
            var info = stat()
            guard fstat(file, &info) == 0 else { throw DaemonFailure.stateSystem(errno) }
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == ownerUID, info.st_mode & 0o7777 & ~0o644 == 0,
                  info.st_nlink == 1 else { throw DaemonFailure.stateUnsafeMetadata }
            guard info.st_size <= off_t(Self.maximumSize) else { throw DaemonFailure.stateTooLarge }
        }
    }

    /// Client side: the requirement the Lab app and CLI place on the daemon connection.
    package enum LabDaemonPin {
        /// The daemon identifier and the hashes the running daemon published. A missing, unsafe or malformed file
        /// throws, so the caller never falls back to its own bundle's daemon or to an unpinned connection.
        package static func requirement(file: LabDaemonIdentityFile = .production) throws -> String {
            try RequirementStrings.lab(identifierHashes: [(BuildIdentifiers.current.daemon, file.read())])
        }
    }

    /// Daemon side: the code-directory hashes of the running process.
    package protocol LabRunningCodeReading: Sendable {
        func runningCdhashes() throws -> [Data]
    }

    /// Reads this process's signing information, then checks the running code against the requirement a client
    /// will build from the result, so a binary replaced on disk after launch is never published.
    package struct LabRunningCode: LabRunningCodeReading {
        package init() {}

        package func runningCdhashes() throws -> [Data] {
            let failure = DaemonFailure(code: .securitySigningInformation)
            var running: SecCode?
            guard SecCodeCopySelf([], &running) == errSecSuccess, let running else { throw failure }
            var onDisk: SecStaticCode?
            guard SecCodeCopyStaticCode(running, [], &onDisk) == errSecSuccess, let onDisk else { throw failure }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(onDisk, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess, let values = information as? [String: Any] else { throw failure }
            let hashes = try CodeIdentity.hashes(
                unique: values[kSecCodeInfoUnique as String] as? Data,
                additional: values[kSecCodeInfoCdHashes as String] as? [Data] ?? [],
            )
            let string = try RequirementStrings.lab(identifierHashes: [(BuildIdentifiers.current.daemon, hashes)])
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(string as CFString, [], &requirement) == errSecSuccess, let requirement,
                  SecCodeCheckValidity(running, [], requirement) == errSecSuccess else { throw failure }
            return hashes
        }
    }
#endif
