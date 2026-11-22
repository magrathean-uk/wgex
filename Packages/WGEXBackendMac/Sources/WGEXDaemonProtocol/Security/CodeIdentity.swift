// SPDX-License-Identifier: MIT
import Foundation

/// Bundle-root derivation from an executable path: pure path arithmetic, so it compiles on every
/// platform and the secure-install inspector can use it without the Security framework.
public enum BundleLayout {
    /// `…/X.app/Contents/MacOS/bin` or `…/X.app/Contents/Helpers/bin` → `…/X.app`.
    public static func root(ofExecutable executableURL: URL) throws -> URL {
        let directory = executableURL.deletingLastPathComponent()
        let contents = directory.deletingLastPathComponent()
        guard ["MacOS", "Helpers"].contains(directory.lastPathComponent), contents.lastPathComponent == "Contents" else {
            throw DaemonFailure(code: .securityInvalidBundleLayout)
        }
        return contents.deletingLastPathComponent()
    }
}

#if os(macOS)
    import Foundation
    import Security
    import WGEXCore
    #if WGEX_LAB_BUILD
        import os
    #endif

    /// Read-only signing identity seam. Tests provide fixed hashes without opening code.
    public protocol CodeIdentityReading: Sendable {
        func cdhashes(at executableURL: URL) throws -> [Data]
    }

    /// Reads Security's truncated code-directory hashes; never launches the binary.
    public struct CodeIdentity: CodeIdentityReading {
        public init() {}

        public func cdhashes(at executableURL: URL) throws -> [Data] {
            var code: SecStaticCode?
            let created = SecStaticCodeCreateWithPath(executableURL as CFURL, [], &code)
            guard created == errSecSuccess, let code else {
                throw DaemonFailure(code: .securitySigningInformation, detail: String(created))
            }
            var hashes = try Self.signingHashes(code)
            // CdHashes covers digest algorithms within one slice. Enumerate fat-file
            // offsets separately so every architecture contributes its own identity.
            let bytes = try Data(contentsOf: executableURL, options: .mappedIfSafe)
            for offset in try Self.sliceOffsets(in: bytes) {
                var slice: SecStaticCode?
                let attributes = [kSecCodeAttributeUniversalFileOffset as String: NSNumber(value: offset)] as CFDictionary
                let status = SecStaticCodeCreateWithPathAndAttributes(executableURL as CFURL, [], attributes, &slice)
                guard status == errSecSuccess, let slice else {
                    throw DaemonFailure(code: .securitySigningInformation, detail: String(status))
                }
                for hash in try Self.signingHashes(slice) where !hashes.contains(hash) {
                    hashes.append(hash)
                }
            }
            return hashes
        }

        private static func signingHashes(_ code: SecStaticCode) throws -> [Data] {
            var information: CFDictionary?
            let copied = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
            guard copied == errSecSuccess, let values = information as? [String: Any] else {
                throw DaemonFailure(code: .securitySigningInformation, detail: String(copied))
            }
            return try Self.hashes(
                unique: values[kSecCodeInfoUnique as String] as? Data,
                additional: values[kSecCodeInfoCdHashes as String] as? [Data] ?? [],
            )
        }

        /// Fat Mach-O headers may use 32- or 64-bit offsets in either byte order.
        /// Thin binaries need no extra slice lookup. Malformed tables fail closed.
        package static func sliceOffsets(in bytes: Data) throws -> [UInt64] {
            guard bytes.count >= 4 else { throw DaemonFailure(code: .securityInvalidExecutable) }
            let magic = Array(bytes.prefix(4))
            let wide: Bool
            let little: Bool
            switch magic {
            case [0xCA, 0xFE, 0xBA, 0xBE]: (wide, little) = (false, false)
            case [0xCA, 0xFE, 0xBA, 0xBF]: (wide, little) = (true, false)
            case [0xBE, 0xBA, 0xFE, 0xCA]: (wide, little) = (false, true)
            case [0xBF, 0xBA, 0xFE, 0xCA]: (wide, little) = (true, true)
            case [0xCE, 0xFA, 0xED, 0xFE], [0xCF, 0xFA, 0xED, 0xFE],
                 [0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF]: return []
            default: throw DaemonFailure(code: .securityInvalidExecutable)
            }
            guard bytes.count >= 8 else { throw DaemonFailure(code: .securityInvalidExecutable) }
            let count = Int(unsigned(bytes, at: 4, count: 4, little: little))
            let stride = wide ? 32 : 20
            guard count > 0, count <= (bytes.count - 8) / stride else { throw DaemonFailure(code: .securityInvalidExecutable) }
            let tableEnd = 8 + count * stride
            return try (0 ..< count).map { index in
                let offset = unsigned(bytes, at: 8 + index * stride + 8, count: wide ? 8 : 4, little: little)
                guard offset >= tableEnd, offset < bytes.count else { throw DaemonFailure(code: .securityInvalidExecutable) }
                return offset
            }
        }

        private static func unsigned(_ bytes: Data, at offset: Int, count: Int, little: Bool) -> UInt64 {
            let values = Array(bytes[offset ..< offset + count])
            return (little ? Array(values.reversed()) : values).reduce(0) { ($0 << 8) | UInt64($1) }
        }

        /// Keeps the running slice and every additional hash, without duplicates.
        package static func hashes(unique: Data?, additional: [Data]) throws -> [Data] {
            guard let unique, unique.count == 20, additional.allSatisfy({ $0.count == 20 }) else {
                throw DaemonFailure(code: .securityMissingHash)
            }
            return ([unique] + additional).reduce(into: []) { hashes, hash in
                if !hashes.contains(hash) {
                    hashes.append(hash)
                }
            }
        }

        /// The app, daemon and CLI share the directory above Contents, including
        /// when the executable lives in Contents/Helpers instead of Contents/MacOS.
        public static func bundleRoot(executableURL: URL) throws -> URL {
            do {
                return try BundleLayout.root(ofExecutable: executableURL)
            } catch {
                throw DaemonFailure(code: .securityInvalidBundleLayout)
            }
        }
    }

    #if WGEX_LAB_BUILD
        /// Lab-only policy builder for the daemon's client checks. Never opens XPC.
        package enum LabPeerRequirements {
            private static let logger = Logger(subsystem: BuildIdentifiers.current.logSubsystem, category: "lab-code-identity")

            /// The app and the CLI installed in `bundle`, measured at each call (DEC-013); the daemon admits each
            /// connection against this, never against values read at its start.
            package static func installedClients(bundle: URL, reader: any CodeIdentityReading) -> String {
                peers(
                    root: bundle, reader: reader,
                    identities: [
                        (BuildIdentifiers.current.app, "Contents/MacOS/WGEX"),
                        (BuildIdentifiers.current.cli, "Contents/Helpers/wgex"),
                    ],
                )
            }

            /// The app alone, for the ADR-030 eligible-reporter check.
            package static func app(executableURL: URL, reader: any CodeIdentityReading) -> String {
                guard let root = try? CodeIdentity.bundleRoot(executableURL: executableURL) else {
                    logger.error("Lab XPC refused: executable is outside the expected bundle layout")
                    return RequirementStrings.labDenyAll
                }
                return peers(root: root, reader: reader, identities: [(BuildIdentifiers.current.app, "Contents/MacOS/WGEX")])
            }

            private static func peers(root: URL, reader: any CodeIdentityReading, identities: [(String, String)]) -> String {
                let clauses = identities.compactMap { identifier, path -> String? in
                    do {
                        return try RequirementStrings.lab(identifierHashes: [(
                            identifier,
                            reader.cdhashes(at: root.appendingPathComponent(path)),
                        )])
                    } catch {
                        // Do not log arbitrary error descriptions or signing information.
                        logger.error("Lab XPC peer omitted: installed signing identity unavailable for \(identifier, privacy: .public)")
                        return nil
                    }
                }
                return clauses.isEmpty ? RequirementStrings.labDenyAll : clauses.joined(separator: " or ")
            }
        }
    #endif
#endif
