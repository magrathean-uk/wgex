// SPDX-License-Identifier: MIT
import os
import WGEXCore
import WGEXDaemonProtocol

public extension DaemonDiagnostics {
    /// Fixed failure code only; callback payloads and adapter error descriptions are withheld.
    static func secretsHandoffFailure(
        _ failure: DaemonFailure, emit: (@Sendable (String) -> Void)? = nil,
    ) {
        let message = "handoff failed, type: UnknownError case: withheld code: \(failure.code)"
        if let emit {
            emit(message)
        } else {
            #if WGEX_LAB_BUILD
                let subsystem = "com.magrathean.WGEXApp.lab"
            #else
                let subsystem = BuildIdentifiers.current.logSubsystem
            #endif
            Logger(subsystem: subsystem, category: "daemon").error("\(message, privacy: .public)")
        }
    }

    /// Operation timing line: fixed step names and integers only, never an error description or any profile or secret text.
    /// Ordinary and Lab builds log it alike; only the subsystem differs, as for the handoff line above.
    static func operationTiming(_ message: String) {
        #if WGEX_LAB_BUILD
            let subsystem = "com.magrathean.WGEXApp.lab"
        #else
            let subsystem = BuildIdentifiers.current.logSubsystem
        #endif
        Logger(subsystem: subsystem, category: "daemon").log("\(message, privacy: .public)")
    }
}

#if WGEX_LAB_BUILD
    import Foundation
    import os
    import Synchronization
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXEngineInterface
    import WGEXProfileStore

    /// Lab-only diagnostics. Unknown errors never contribute a description, type name or payload.
    extension DaemonDiagnostics {
        private static let pfSpawns = Mutex<UInt64>(0)

        /// Counts real fixed-executable spawns; enable-reference values are always withheld.
        package static func packetFilterSpawn(_ arguments: [String]) {
            let count = pfSpawns.withLock { $0 += 1; return $0 }
            let fields = packetFilterArguments(arguments)
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").log(
                "PF spawn count: \(count, privacy: .public) argv: \(fields, privacy: .public)",
            )
        }

        package static func packetFilterArguments(_ arguments: [String]) -> String {
            guard let first = arguments.first else { return "<withheld>" }
            if first == "-X" {
                return "-X <withheld>"
            }
            if ["-E", "-e"].contains(first) {
                return first
            }
            guard arguments.count > 1 else { return "<withheld>" }
            let second = arguments[1]
            if (first == "-a" && ["com.apple", "com.apple/wgex"].contains(second))
                || (first == "-o" && second == "none")
                || (first == "-s" && ["info", "rules", "References"].contains(second))
            {
                return first + " " + second
            }
            if first == "-i", (try? PFInterface(second)) != nil {
                return first + " " + second
            }
            return "<withheld>"
        }

        /// Only PF parser/kernel error vocabulary is permitted; profile and credential text is never accepted.
        package static func packetFilterStderr(_ stderr: String) -> String {
            let allowed = [
                "DIOC",
                "syntax error",
                "unknown interface",
                "no IP address found",
                "rules not loaded",
                "Device not configured",
                "Invalid argument",
                "Operation not supported",
                "Permission denied",
                "Cannot allocate memory",
                "cannot open",
                "No such file or directory",
            ]
            let lines = stderr.split(separator: "\n").filter { line in
                guard line.hasPrefix("pfctl:") || line.hasPrefix("stdin:"),
                      line.utf8.allSatisfy({ $0 >= 32 && $0 < 127 }), allowed.contains(where: { line.contains($0) }) else { return false }
                let lower = line.lowercased()
                guard !["key", "secret", "token", "password", "credential", "cookie"].contains(where: { lower.contains($0) })
                else { return false }
                return line.range(of: "[A-Za-z0-9+/=_-]{32,}", options: .regularExpression) == nil
            }
            return String(decoding: lines.joined(separator: "\n").utf8.prefix(512), as: UTF8.self)
        }

        package static func packetFilterFailure(status: Int32, stderr: String) {
            let diagnostic = packetFilterStderr(stderr)
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").error(
                "PF command failed, status: \(status, privacy: .public) stderr: \(diagnostic, privacy: .public)",
            )
        }

        /// Reports successful engine rollback without exposing configuration or adapter text.
        public static func configurationRestored() {
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").log("Engine restored the previous live configuration")
        }

        /// Emits fixed allowlisted names, case labels and integer codes only.
        public static func log(_ error: any Error, context: StaticString) {
            let fields = fields(for: error)
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").log(
                "\(context, privacy: .public) failed, type: \(fields.type, privacy: .public) case: \(fields.label, privacy: .public) code: \(fields.code, privacy: .public)",
            )
        }

        package static func fields(for error: any Error) -> (type: String, label: String, code: Int32) {
            switch error {
            case let failure as DaemonFailure:
                let row = DaemonFailure.catalog[failure.kind]
                return (
                    row?.diagnosticType ?? "UnknownError",
                    row?.diagnosticLabel ?? "withheld",
                    failure.systemStatus ?? captiveCode(failure),
                )
            case let failure as EngineError: return engineFields(failure)
            case let failure as SecretStoreError: return secretFields(failure)
            default: return ("UnknownError", "withheld", -1)
            }
        }

        private static func captiveCode(_ failure: DaemonFailure) -> Int32 {
            switch failure.kind {
            case .captiveUnavailable, .captiveDNSFailed, .captiveRoutesFailed, .captivePolicyFailed: Int32(failure.code)
            default: -1
            }
        }

        private static let engineFields: [EngineError: (String, Int32)] = [
            .invalidArgument: ("invalidArgument", -1), .outOfMemory: ("outOfMemory", -2),
            .invalidHandle: ("invalidHandle", -3), .tun: ("tun", -4), .bind: ("bind", -5),
            .config: ("config", -6), .up: ("up", -7), .state: ("state", -8), .abiMismatch: ("abiMismatch", -8),
            .deviceClosed: ("deviceClosed", -9), .internal: ("internal", -99),
        ]

        private static func engineFields(_ error: EngineError) -> (type: String, label: String, code: Int32) {
            if case let .unknown(code) = error {
                return ("EngineError", "unknown", code)
            }
            let fields = engineFields[error] ?? ("unknown", -99)
            return ("EngineError", fields.0, fields.1)
        }

        private static func secretFields(_ error: SecretStoreError) -> (type: String, label: String, code: Int32) {
            switch error {
            case .locked: ("SecretStoreError", "locked", -1)
            case .notFound: ("SecretStoreError", "notFound", -1)
            case .duplicate: ("SecretStoreError", "duplicate", -1)
            case let .system(code): ("SecretStoreError", "system", code)
            case .unavailable: ("SecretStoreError", "unavailable", -1)
            }
        }
    }
#endif
