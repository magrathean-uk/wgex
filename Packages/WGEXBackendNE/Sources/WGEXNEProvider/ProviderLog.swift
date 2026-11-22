// SPDX-License-Identifier: MIT

import Foundation
import OSLog
import WGEXCore
import WGEXEngineInterface

/// Receives the provider's log lines: fixed text with enumerated values only, and engine lines scrubbed of anything
/// shaped like a key. The extension shell forwards them to the shared log.
public protocol ProviderLogSink: Sendable {
    func write(_ line: String)
}

/// The default sink writes to the unified log; the lines are public because they carry no secrets.
public struct UnifiedProviderLogSink: ProviderLogSink {
    private static let logger = Logger(subsystem: "wgex", category: "provider")
    public init() {}
    public func write(_ line: String) {
        Self.logger.notice("\(line, privacy: .public)")
    }
}

/// The newest lines, with the time each was written, for the `.logs(since:)` reply. Bounded in count and line length so
/// a full reply stays far below the codec's limit.
package struct ProviderLogRing {
    package static let limit = 256
    private var entries: [(date: Date, line: String)] = []

    package init() {}

    package mutating func append(_ line: String, at date: Date) {
        entries.append((date, line))
        if entries.count > Self.limit {
            entries.removeFirst(entries.count - Self.limit)
        }
    }

    package func lines(since: Date?) -> [String] {
        entries.filter { entry in since.map { entry.date >= $0 } ?? true }.map(\.line)
    }
}

package enum ProviderLogText {
    package static let maximumLength = 300
    /// A 32-byte key is 43 or 44 base64 characters or 64 hex characters; any shorter run is kept.
    package static let redactedRun = 40

    private static let failureNames: [TunnelError: String] = [
        .anotherTunnelActive: "another tunnel is active", .revisionConflict: "revision conflict", .busy: "busy",
        .secretsUnavailable: "secrets unavailable", .backendUnavailable: "backend unavailable",
        .serviceRecovering: "service recovering", .permissionDenied: "permission denied", .timedOut: "timed out",
        .cancelled: "cancelled",
    ]

    /// Fixed text per failure; a profile id is never included.
    package static func failure(_ error: TunnelError) -> String {
        switch error {
        case .profileNotFound: "profile not found"
        case let .invalidConfiguration(reason): "invalid configuration (\(reason.rawValue))"
        case let .engine(code): "engine error \(code)"
        default: failureNames[error] ?? "failure"
        }
    }

    package static func engine(_ line: EngineLogLine) -> String {
        let level = switch line.level {
        case .debug: "debug"
        case .info: "info"
        case .error: "error"
        }
        return "Engine \(level): \(scrub(line.message))"
    }

    /// Replaces each run of `redactedRun` or more base64, base64url or hex characters with a marker and each control
    /// character with a space, then bounds the length. Truncation runs last, so it never exposes part of a key.
    package static func scrub(_ message: String) -> String {
        var output = ""
        var run = ""
        func flush() {
            output += run.count >= redactedRun ? "(redacted)" : run
            run = ""
        }
        for character in message {
            if character.isASCII, character.isLetter || character.isNumber || "+/=_-".contains(character) {
                run.append(character)
                continue
            }
            flush()
            let control = character.unicodeScalars.contains { $0.properties.generalCategory == .control }
            output.append(control || character.isNewline ? " " : character)
        }
        flush()
        return String(output.prefix(maximumLength))
    }
}
