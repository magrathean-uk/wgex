// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation

public struct OriginalText: Codable, Sendable, Hashable {
    /// Parsed secrets use "$WGEX_SECRET:<ref-id>$"; other key-shaped tokens use "$WGEX_REDACTED$".
    /// Ignored directive values, including inline comments, become "<removed>".
    public var text: String
    public var sha256OfOriginal: Data
    /// Digest of restored export bytes after irreversible redaction, before secret placeholder insertion.
    /// Absent in legacy documents and imports that need no irreversible redaction.
    public var sha256OfRedactedOriginal: Data?

    /// True when original export cannot reproduce the import byte for byte.
    public var wasRedacted: Bool {
        sha256OfRedactedOriginal != nil
    }

    public init(text: String, sha256OfOriginal: Data) {
        self.init(text: text, sha256OfOriginal: sha256OfOriginal, sha256OfRedactedOriginal: nil)
    }

    public init(text: String, sha256OfOriginal: Data, sha256OfRedactedOriginal: Data?) {
        self.text = text; self.sha256OfOriginal = sha256OfOriginal
        self.sha256OfRedactedOriginal = sha256OfRedactedOriginal
    }

    package init(
        redacting raw: UnsafeRawBufferPointer, secrets: [(Range<Int>, String)], publicKeys: [Range<Int>],
        ignoredValues: [Range<Int>] = [],
    ) {
        let protected = (secrets.map(\.0) + publicKeys + ignoredValues).sorted { $0.lowerBound < $1.lowerBound }
        let redactions = OriginalKeyRedactor.ranges(in: raw, excluding: protected)
        let marker = "$WGEX_REDACTED$"
        let irreversible = (redactions.map { ($0, marker) } + ignoredValues.map { ($0, "<removed>") })
            .sorted { $0.0.lowerBound < $1.0.lowerBound }
        let replacements = (secrets + irreversible).sorted { $0.0.lowerBound < $1.0.lowerBound }
        var publicBytes: [UInt8] = []; publicBytes.reserveCapacity(raw.count)
        defer {
            publicBytes.withUnsafeMutableBytes { bytes in
                if let base = bytes.baseAddress {
                    _ = memset_s(base, bytes.count, 0, bytes.count)
                }
            }
        }
        var cursor = 0
        for (range, replacement) in replacements {
            publicBytes.append(contentsOf: raw[cursor ..< range.lowerBound])
            publicBytes.append(contentsOf: replacement.utf8); cursor = range.upperBound
        }
        publicBytes.append(contentsOf: raw[cursor ..< raw.count])
        text = String(decoding: publicBytes, as: UTF8.self)
        sha256OfOriginal = OriginalKeyRedactor.hash(raw, replacing: [])
        sha256OfRedactedOriginal = irreversible.isEmpty ? nil : OriginalKeyRedactor.hash(raw, replacing: irreversible)
    }
}

private enum OriginalKeyRedactor {
    /// Scan borrowed bytes only. Commented-out public keys are deliberately redacted too.
    /// Match conservatively even beside other token characters; no secret-bearing copies are made.
    static func ranges(in raw: UnsafeRawBufferPointer, excluding protected: [Range<Int>]) -> [Range<Int>] {
        var result: [Range<Int>] = []
        var cursor = 0
        for range in protected + [raw.count ..< raw.count] {
            while cursor < range.lowerBound {
                let count = KeyShape.tokenLength(in: raw, at: cursor, end: range.lowerBound)
                if count > 0 {
                    result.append(cursor ..< cursor + count)
                }
                cursor += max(count, 1)
            }
            cursor = range.upperBound
        }
        return result
    }

    static func hash(_ raw: UnsafeRawBufferPointer, replacing replacements: [(Range<Int>, String)]) -> Data {
        var hasher = SHA256()
        var cursor = 0
        for (range, replacement) in replacements {
            hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: raw[cursor ..< range.lowerBound]))
            Array(replacement.utf8).withUnsafeBytes { hasher.update(bufferPointer: $0) }
            cursor = range.upperBound
        }
        hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: raw[cursor ..< raw.count]))
        return Data(hasher.finalize())
    }
}
