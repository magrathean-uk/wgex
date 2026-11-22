// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct ByteCodecTests {
    @Test(arguments: [
        ("", ""),
        ("f", "Zg=="),
        ("f" + "o", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ])
    func `RFC 4648 base64 vectors`(plain: String, encoded: String) throws {
        let input = Array(plain.utf8)
        var output = [UInt8](repeating: 0, count: encoded.utf8.count)
        try input
            .withUnsafeBytes { source in try output.withUnsafeMutableBytes { try ByteCodec.encode(source, into: $0, encoding: .base64) } }
        #expect(output == Array(encoded.utf8))
        var decoded = [UInt8](repeating: 0, count: input.count)
        try output
            .withUnsafeBytes { source in try decoded.withUnsafeMutableBytes { try ByteCodec.decode(source, into: $0, encoding: .base64) } }
        #expect(decoded == input)
    }

    @Test(arguments: ["Zh==", "Zg=+", "Zg--", "Zg_+", "Z===", "====", "Zg==\n", "Zg"])
    func `base64 rejects noncanonical encodings and wipes partial output`(text: String) {
        var target = [UInt8](repeating: 0xA5, count: 1)
        let bytes = Array(text.utf8)
        #expect(throws: ByteCodecError.self) {
            try bytes.withUnsafeBytes { source in try target.withUnsafeMutableBytes { try ByteCodec.decode(
                source,
                into: $0,
                encoding: .base64,
            ) } }
        }
        #expect(target == [0])
    }

    @Test
    func `all byte values round trip in every encoding`() throws {
        for encoding in [KeyEncoding.raw, .hex, .base64] {
            for count in 0 ... 256 {
                let input = (0 ..< count).map { UInt8(truncatingIfNeeded: $0) }
                var encoded = [UInt8](repeating: 0, count: ByteCodec.encodedCount(count, encoding: encoding))
                var decoded = [UInt8](repeating: 0, count: count)
                try input.withUnsafeBytes { source in try encoded.withUnsafeMutableBytes { try ByteCodec.encode(
                    source,
                    into: $0,
                    encoding: encoding,
                ) } }
                try encoded.withUnsafeBytes { source in try decoded.withUnsafeMutableBytes { try ByteCodec.decode(
                    source,
                    into: $0,
                    encoding: encoding,
                ) } }
                #expect(decoded == input)
            }
        }
    }

    @Test
    func `hex accepts both cases and rejects partial invalid input`() throws {
        var decoded = [UInt8](repeating: 0, count: 3)
        try Array("00aAFF".utf8).withUnsafeBytes { source in
            try decoded.withUnsafeMutableBytes { try ByteCodec.decode(source, into: $0, encoding: .hex) }
        }
        #expect(decoded == [0, 170, 255])
        #expect(throws: ByteCodecError.invalidEncoding) {
            try Array("00aaFg".utf8).withUnsafeBytes { source in
                try decoded.withUnsafeMutableBytes { try ByteCodec.decode(source, into: $0, encoding: .hex) }
            }
        }
        #expect(decoded == [0, 0, 0])
    }
}
