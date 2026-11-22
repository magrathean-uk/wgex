// SPDX-License-Identifier: MIT

/// Conservative recognition of 32-byte key shapes; never retains matched bytes.
public enum KeyShape {
    /// A standard/base64url token, padded or unpadded, or hexadecimal bytes.
    public enum Kind: Sendable, Hashable { case base64, hex }

    /// UTF-8 byte range and shape, without the matched value.
    public struct Match: Sendable, Hashable {
        /// UTF-8 offsets of the recognised token.
        public let range: Range<Int>
        /// Encoding family; values are never retained.
        public let kind: Kind
    }

    /// Checks borrowed public-field bytes without copying key material.
    public static func contains(in bytes: some Collection<UInt8>) -> Bool {
        var standard = 0; var url = 0; var hex = 0
        for byte in bytes {
            standard = isBase64(byte, url: false) ? standard + 1 : 0
            url = isBase64(byte, url: true) ? url + 1 : 0
            hex = isHex(byte) ? hex + 1 : 0
            if standard >= 43 || url >= 43 || hex >= 64 {
                return true
            }
        }
        return false
    }

    /// Scans conservatively even beside token characters; hexadecimal takes precedence.
    public static func matches(in bytes: UnsafeRawBufferPointer, includeFragments: Bool = false, wholeTokens: Bool = false) -> [Match] {
        var result: [Match] = []
        var start = 0
        while start < bytes.count {
            var length = tokenLength(in: bytes, at: start, end: bytes.count)
            if includeFragments, length == 0, bytes.count - start >= 42 {
                let prefix = bytes[start ..< start + 42]
                if prefix.allSatisfy({ isBase64($0, url: false) }) || prefix.allSatisfy({ isBase64($0, url: true) }) {
                    length = 42
                }
            }
            if includeFragments, length == 43, bytes.count - start > 43,
               isBase64(bytes[start + 43], url: false) || isBase64(bytes[start + 43], url: true)
            {
                length = 44
            }
            let hex = length == 64
            let before = start > 0 && (hex ? isHex(bytes[start - 1]) : isBase64(bytes[start - 1], url: false) || isBase64(
                bytes[start - 1],
                url: true,
            ))
            let after = start + length < bytes
                .count && (hex ? isHex(bytes[start + length]) : isBase64(bytes[start + length], url: false) || isBase64(
                    bytes[start + length],
                    url: true,
                ))
            if length > 0, !wholeTokens || (!before && !after) {
                result.append(Match(range: start ..< start + length, kind: length == 64 ? .hex : .base64))
            }
            start += max(length, 1)
        }
        return result
    }

    /// Length of a key-shaped token at a byte offset, bounded by `end`.
    public static func tokenLength(in bytes: UnsafeRawBufferPointer, at start: Int, end: Int) -> Int {
        guard start >= 0, end <= bytes.count, start < end else { return 0 }
        if end - start >= 64, bytes[start ..< start + 64].allSatisfy(isHex) {
            return 64
        }
        guard end - start >= 43 else { return 0 }
        let prefix = bytes[start ..< start + 43]
        guard prefix.allSatisfy({ isBase64($0, url: false) }) || prefix.allSatisfy({ isBase64($0, url: true) }) else { return 0 }
        return end - start >= 44 && bytes[start + 43] == 61 ? 44 : 43
    }

    private static func isBase64(_ byte: UInt8, url: Bool) -> Bool {
        (65 ... 90).contains(byte) || (97 ... 122).contains(byte) || (48 ... 57).contains(byte) ||
            (url ? byte == 45 || byte == 95 : byte == 43 || byte == 47)
    }

    private static func isHex(_ byte: UInt8) -> Bool {
        (48 ... 57).contains(byte) || (65 ... 70).contains(byte) || (97 ... 102).contains(byte)
    }
}
