// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Finds key material in test output: WireGuard-key-shaped standard/base64url (43
/// characters with optional padding), 64-character hex, and any secret registered
/// with ``register(_:)`` in raw, base64 or hex form. Findings carry a kind
/// and an offset, never the matched text.
public struct SecretScanner: Sendable {
    /// What a finding is.
    public enum FindingKind: Sendable, Hashable {
        /// Standard/base64url, padded or unpadded.
        case keyShapedBase64
        /// 64 hexadecimal characters.
        case hex64
        /// A registered secret.
        case registeredSecret
    }

    /// One finding.
    public struct Finding: Sendable, Hashable {
        /// What was found.
        public let kind: FindingKind
        /// UTF-8 byte offset of the match.
        public let offset: Int
    }

    private var registered: [Data] = []

    /// Creates a scanner with no registered secrets.
    public init() {}

    /// Registers a secret to look for (kept only in this scanner's memory).
    public mutating func register(_ secret: borrowing SecretBytes) {
        let raw = secret.withUnsafeBytes { Data($0) }
        registered.append(raw)
        registered.append(Data(raw.base64EncodedString().utf8))
        registered.append(Data(raw.map { String(format: "%02x", $0) }.joined().utf8))
    }

    /// Findings in `text`.
    public func findings(in text: String) -> [Finding] {
        findings(in: Data(text.utf8))
    }

    /// Findings in `data`, in offset order.
    public func findings(in data: Data) -> [Finding] {
        var results = shapedFindings(in: Array(data))
        for needle in registered where !needle.isEmpty {
            var searchStart = data.startIndex
            while let range = data.range(of: needle, in: searchStart ..< data.endIndex) {
                results.append(Finding(kind: .registeredSecret, offset: range.lowerBound - data.startIndex))
                searchStart = range.upperBound
            }
        }
        return results.sorted { ($0.offset, "\($0.kind)") < ($1.offset, "\($1.kind)") }
    }

    /// True when nothing secret-shaped or registered appears in `text`.
    public func isClean(_ text: String) -> Bool {
        findings(in: text).isEmpty
    }

    private func shapedFindings(in bytes: [UInt8]) -> [Finding] {
        bytes.withUnsafeBytes { raw in
            KeyShape.matches(in: raw, wholeTokens: true).map { match in
                Finding(kind: match.kind == .hex ? .hex64 : .keyShapedBase64, offset: match.range.lowerBound)
            }
        }
    }
}
