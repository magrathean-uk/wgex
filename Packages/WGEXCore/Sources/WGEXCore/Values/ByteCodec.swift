// SPDX-License-Identifier: MIT
import Foundation

public enum KeyEncoding: Sendable { case raw, base64, hex }

public enum ByteCodecError: Error, Sendable, Hashable { case invalidEncoding, invalidLength }

/// Strict, canonical codecs. Neither input nor output passes through String or Data.
public enum ByteCodec {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    private static let hexadecimal = Array("0123456789abcdef".utf8)

    public static func encodedCount(_ count: Int, encoding: KeyEncoding) -> Int {
        switch encoding { case .raw: count; case .hex: count * 2; case .base64: (count + 2) / 3 * 4 }
    }

    public static func encode(
        _ source: UnsafeRawBufferPointer, into target: UnsafeMutableRawBufferPointer, encoding: KeyEncoding,
    ) throws(ByteCodecError) {
        guard target.count == encodedCount(source.count, encoding: encoding) else { throw .invalidLength }
        switch encoding {
        case .raw: target.copyMemory(from: source)
        case .hex:
            for index in source.indices {
                target[index * 2] = hexadecimal[Int(source[index] >> 4)]
                target[index * 2 + 1] = hexadecimal[Int(source[index] & 15)]
            }
        case .base64:
            for offset in stride(from: 0, to: source.count, by: 3) {
                let a = source[offset]
                let b = offset + 1 < source.count ? source[offset + 1] : 0
                let c = offset + 2 < source.count ? source[offset + 2] : 0
                let out = offset / 3 * 4
                target[out] = alphabet[Int(a >> 2)]
                target[out + 1] = alphabet[Int((a & 3) << 4 | b >> 4)]
                target[out + 2] = offset + 1 < source.count ? alphabet[Int((b & 15) << 2 | c >> 6)] : 61
                target[out + 3] = offset + 2 < source.count ? alphabet[Int(c & 63)] : 61
            }
        }
    }

    /// On any failure the entire destination is wiped before throwing.
    public static func decode(
        _ source: UnsafeRawBufferPointer, into target: UnsafeMutableRawBufferPointer, encoding: KeyEncoding,
    ) throws(ByteCodecError) {
        var succeeded = false
        defer {
            if !succeeded, let base = target.baseAddress {
                _ = memset_s(base, target.count, 0, target.count)
            }
        }
        guard source.count == encodedCount(target.count, encoding: encoding) else { throw .invalidLength }
        switch encoding {
        case .raw: target.copyMemory(from: source)
        case .hex:
            for index in target.indices {
                target[index] = try nibble(source[index * 2]) << 4 | nibble(source[index * 2 + 1])
            }
        case .base64:
            try decodeBase64(source, into: target)
        }
        succeeded = true
    }

    private static func decodeBase64(
        _ source: UnsafeRawBufferPointer, into target: UnsafeMutableRawBufferPointer,
    ) throws(ByteCodecError) {
        for offset in stride(from: 0, to: source.count, by: 4) {
            let out = offset / 4 * 3
            let remaining = target.count - out
            let a = try sextet(source[offset]); let b = try sextet(source[offset + 1])
            let c: UInt8 = remaining > 1 ? try sextet(source[offset + 2]) : 0
            let d: UInt8 = remaining > 2 ? try sextet(source[offset + 3]) : 0
            if remaining == 1 {
                guard source[offset + 2] == 61, source[offset + 3] == 61, b & 15 == 0 else { throw .invalidEncoding }
            } else if remaining == 2 {
                guard source[offset + 3] == 61, c & 3 == 0 else { throw .invalidEncoding }
            }
            target[out] = a << 2 | b >> 4
            if remaining > 1 {
                target[out + 1] = b << 4 | c >> 2
            }
            if remaining > 2 {
                target[out + 2] = c << 6 | d
            }
        }
    }

    private static func sextet(_ byte: UInt8) throws(ByteCodecError) -> UInt8 {
        switch byte {
        case 65 ... 90: byte - 65
        case 97 ... 122: byte - 71
        case 48 ... 57: byte + 4
        case 43: 62
        case 47: 63
        default: throw .invalidEncoding
        }
    }

    private static func nibble(_ byte: UInt8) throws(ByteCodecError) -> UInt8 {
        switch byte {
        case 48 ... 57: byte - 48
        case 65 ... 70: byte - 55
        case 97 ... 102: byte - 87
        default: throw .invalidEncoding
        }
    }
}
