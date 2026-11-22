// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
import WGEXCore

/// Exact and pattern matches are collected on the original input and their union is replaced once.
/// Use one instance for an entire export so tokens correlate across all entries.
/// Callers supply store secrets and private metadata; no store dependency is introduced.
public final class Redactor: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private struct State: Sendable {
        let key = SymmetricKey(size: .bits256)
        var tokens: [Data: String] = [:]
        var matches: [Int: [UInt8: [Data: String]]] = [:]
        var nextToken = 1

        func fingerprint(_ bytes: some Collection<UInt8>) -> Data {
            Data(HMAC<SHA256>.authenticationCode(for: Data(bytes), using: key))
        }

        mutating func token(for bytes: some Collection<UInt8>) -> String {
            let digest = fingerprint(bytes)
            if let existing = tokens[digest] {
                return existing
            }
            let token = "<secret:\(nextToken)>"
            nextToken += 1; tokens[digest] = token
            return token
        }

        mutating func insert(_ bytes: some Collection<UInt8>, token: String) {
            guard let first = bytes.first else { return }
            matches[bytes.count, default: [:]][first, default: [:]][fingerprint(bytes)] = token
        }

        mutating func register(_ bytes: some Collection<UInt8>) {
            guard !bytes.isEmpty else { return }
            let token = token(for: bytes)
            insert(bytes, token: token)
            if bytes.count >= 12 {
                var start = bytes.startIndex
                while let end = bytes.index(start, offsetBy: 12, limitedBy: bytes.endIndex) {
                    insert(bytes[start ..< end], token: token)
                    bytes.formIndex(after: &start)
                }
            }
        }
    }

    // Test seam: while true on the current task, `redact` returns its input unchanged. It exists so a control run can prove
    // a leak search is able to fail. Compiled for DEBUG and test builds only, so Release has no redaction-disable switch.
    #if DEBUG
        @TaskLocal package static var bypassForTesting = false
    #endif

    private let state = Mutex(State())
    public let includeEndpoints: Bool
    public var description: String {
        "<Redactor>"
    }

    public var debugDescription: String {
        description
    }

    public init(exactMatches: [String] = [], includeEndpoints: Bool = false) {
        self.includeEndpoints = includeEndpoints
        register(exactMatches)
    }

    /// For non-secret identifiers only: profile names, SSIDs, hosts and paths.
    /// Register key material through the borrowed SecretBytes or raw-buffer overload.
    /// Registration order determines token numbering. Empty values are ignored.
    public func register(_ exactMatches: [String]) {
        state.withLock { state in
            for value in exactMatches where !value.isEmpty {
                let token = state.token(for: value.utf8)
                state.insert(value.utf8, token: token)
                let characters = Array(value)
                if characters.count >= 12 {
                    for offset in 0 ... characters.count - 12 {
                        state.insert(String(characters[offset ..< offset + 12]).utf8, token: token)
                    }
                }
            }
        }
    }

    /// Registers borrowed secret text bytes without creating a String or retaining a byte copy.
    /// Only keyed fingerprints and token lengths are retained, including 12-byte windows.
    public func register(_ secret: borrowing SecretBytes) {
        secret.withUnsafeBytes { register($0) }
    }

    /// The caller owns and wipes the borrowed storage. No pointer escapes registration.
    public func register(_ bytes: UnsafeRawBufferPointer) {
        state.withLock { $0.register(bytes) }
    }

    /// Internal inspection seam: the complete set of retained Strings contains replacement labels only.
    package var retainedStrings: [String] {
        state.withLock { Array($0.tokens.values) + $0.matches.values.flatMap { $0.values.flatMap(\.values) } }
    }

    private struct Span {
        var range: NSRange
        let token: String
        let exact: Bool
    }

    /// Scalar boundaries in UTF-8 map to NSString offsets; interior bytes remain invalid boundaries.
    package static func utf16Offsets(_ text: String) -> [Int] {
        var offsets = [Int](repeating: -1, count: text.utf8.count + 1)
        var byteOffset = 0; var utf16Offset = 0
        for scalar in text.unicodeScalars {
            offsets[byteOffset] = utf16Offset
            byteOffset += scalar.utf8.count; utf16Offset += scalar.utf16.count
        }
        offsets[byteOffset] = utf16Offset
        return offsets
    }

    public func redact(_ text: String) -> String {
        #if DEBUG
            if Self.bypassForTesting {
                return text
            }
        #endif
        return state.withLock { state in
            let bytes = Array(text.utf8)
            // Ignore physical log line breaks for exact matches, retaining original offsets.
            let positions = bytes.indices.filter { bytes[$0] != 10 && bytes[$0] != 13 }
            let compact = positions.map { bytes[$0] }
            let utf16Offsets = Self.utf16Offsets(text)
            var spans: [Span] = []
            for start in compact.indices {
                for (length, firstBytes) in state.matches where length <= compact.count - start {
                    guard let candidates = firstBytes[compact[start]],
                          let token = candidates[state.fingerprint(compact[start ..< start + length])] else { continue }
                    let lower = utf16Offsets[positions[start]]
                    let upperByte = positions[start + length - 1] + 1
                    let upper = utf16Offsets[upperByte]
                    if lower >= 0, upper > lower {
                        spans.append(Span(
                            range: NSRange(location: lower, length: upper - lower),
                            token: token,
                            exact: true,
                        ))
                    }
                }
            }
            guard let patterns = patternSpans(
                text, positions: positions, compact: compact, utf16Offsets: utf16Offsets, state: &state,
            ) else { return "<redacted>" }
            spans += patterns
            var merged: [Span] = []
            for span in spans.sorted(by: { $0.range.location < $1.range.location }) {
                if let last = merged.last, NSMaxRange(last.range) >= span.range.location {
                    let end = max(NSMaxRange(last.range), NSMaxRange(span.range))
                    let preferred = span.exact && !last.exact ? span : last
                    merged[merged.count - 1] = Span(
                        range: NSRange(location: last.range.location, length: end - last.range.location),
                        token: preferred.token, exact: preferred.exact,
                    )
                } else {
                    merged.append(span)
                }
            }
            let result = NSMutableString(string: text)
            for span in merged.reversed() {
                result.replaceCharacters(in: span.range, with: span.token)
            }
            return result as String
        }
    }

    private struct Rule: Sendable {
        let regex: NSRegularExpression?
        let group: Int
        let address: Bool

        /// Patterns are constants covered by tests; a rule that fails to compile fails closed in `patterns`.
        init(expression: String, group: Int, address: Bool) {
            regex = try? NSRegularExpression(pattern: expression)
            self.group = group
            self.address = address
        }
    }

    private static let rules: [Rule] = [
        Rule(expression: #"(?im)^\s*(?:search\s+domain(?:\[\d+\])?|domain)\s*:\s*(\S+)"#, group: 1, address: false),
        Rule(expression: #"(?im)\b(?:PrivateKey|PresharedKey)\s*=\s*([^\r\n]+)"#, group: 1, address: false),
        Rule(expression: #"(?i)["']?\b(?:path|sni|host)["']?\s*[:=]\s*["']([^"'\r\n]+)["']"#, group: 1, address: false),
        Rule(expression: #"(?i)\b(?:path|sni|host)\s*[:=]\s*([^\s,"'}]+)"#, group: 1, address: false),
        Rule(expression: #"(?i)\b[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\b"#, group: 0, address: false),
        // IPv6 runs before IPv4 so an embedded IPv4 tail stays inside one token. Only the full
        // eight-group form or a form containing "::" qualifies, so clock times are left alone.
        Rule(
            expression: #"(?i)(?<![a-f0-9:.])(?:(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}|(?:[a-f0-9]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}|(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4})*)?::(?:(?:[a-f0-9]{1,4}:)*(?:(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{1,4}))?)(?:%[a-z0-9_.-]+)?(?:/\d{1,3})?(?![a-f0-9:])"#,
            group: 0,
            address: true,
        ),
        Rule(
            expression: #"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\d|\.\d)|(?<![\d.])\d{1,3}(?:\.\d{1,3}){0,2}/\d{1,2}(?!\d)"#,
            group: 0,
            address: true,
        ),
    ]

    /// Both pattern and exact spans refer to the complete original input.
    private func patternSpans(
        _ text: String, positions: [Int], compact: [UInt8], utf16Offsets: [Int], state: inout State,
    ) -> [Span]? {
        let source = text as NSString
        var spans: [Span] = []
        compact.withUnsafeBytes { raw in
            for match in KeyShape.matches(in: raw, includeFragments: true) {
                let lower = positions[match.range.lowerBound]
                let upper = positions[match.range.upperBound - 1] + 1
                let start = utf16Offsets[lower], end = utf16Offsets[upper]
                guard start >= 0, end > start else { continue }
                spans.append(Span(
                    range: NSRange(location: start, length: end - start),
                    token: state.token(for: compact[match.range]),
                    exact: false,
                ))
            }
        }

        for rule in Self.rules {
            guard let regex = rule.regex else { return nil }
            guard !(rule.address && includeEndpoints) else { continue }
            for match in regex.matches(in: text, range: NSRange(location: 0, length: source.length)) {
                let range = match.range(at: rule.group)
                guard range.location != NSNotFound, range.length > 0 else { continue }
                let value = source.substring(with: range)
                if includeEndpoints, rule.group == 1, (try? IPAddressRange(value)) != nil {
                    continue
                }
                spans.append(Span(range: range, token: state.token(for: value.utf8), exact: false))
            }
        }
        return spans
    }
}
