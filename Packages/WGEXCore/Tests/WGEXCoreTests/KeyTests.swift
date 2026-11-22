// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct KeyTests {
    /// RFC 7748 section 6.1; published test vectors, never operational keys.
    private static let alice: [UInt8] = [
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D, 0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
        0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A, 0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A,
    ]
    private static let alicePublic: [UInt8] = [
        0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, 0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
        0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, 0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
    ]
    private static let bob: [UInt8] = [
        0x5D, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B, 0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80, 0x0E, 0xE6,
        0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD, 0x1C, 0x2F, 0x8B, 0x27, 0xFF, 0x88, 0xE0, 0xEB,
    ]
    private static let bobPublic: [UInt8] = [
        0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4, 0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
        0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D, 0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F,
    ]

    @Test(arguments: [(alice, alicePublic), (bob, bobPublic)])
    func `X25519 derivation matches RFC 7748`(raw: [UInt8], expected: [UInt8]) throws {
        let source = try Self.secret(raw)
        let key = try PrivateKey(bytes: consume source)
        let derived = try key.publicKey()
        #expect(derived.rawValue == Data(expected))
    }

    @Test(arguments: ["client1", "client2", "server"])
    func `derivation matches known WireGuard fixture pairs`(name: String) throws {
        var privateText = try Self.fixture(name + ".key")
        let encoded = try SecretBytes(wiping: &privateText)
        let key = try PrivateKey(parsing: encoded, encoding: .base64)
        let expected = try Self.fixture(name + ".pub").withUnsafeBytes { try PublicKey(parsing: $0, encoding: .base64) }
        #expect(try key.publicKey() == expected)
    }

    @Test
    func `RT-01 one thousand keys are distinct and clamped in every build configuration`() throws {
        var publicKeys = Set<PublicKey>()
        for _ in 0 ..< 1000 {
            let key = try PrivateKey.generate()
            var exported = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &exported)
            let clamped = exported.withUnsafeBytes { $0[0] & 7 == 0 && $0[31] & 128 == 0 && $0[31] & 64 == 64 }
            #expect(clamped)
            let derived = try key.publicKey()
            #expect(publicKeys.insert(derived).inserted)
        }
        #expect(publicKeys.count == 1000)
    }

    @Test
    func `private and preshared key codecs stay in wiped containers`() throws {
        let raw = try Self.secret(Self.alice)
        let key = try PrivateKey(parsing: raw)
        let psk = try PresharedKey(parsing: raw)
        for encoding in [KeyEncoding.raw, .base64, .hex] {
            var encoded = try SecretBytes(zeroedCount: ByteCodec.encodedCount(32, encoding: encoding))
            try key.encode(into: &encoded, encoding: encoding)
            let decoded = try PrivateKey(parsing: encoded, encoding: encoding)
            var roundTrip = try SecretBytes(zeroedCount: 32)
            try decoded.encode(into: &roundTrip)
            let equal = roundTrip.constantTimeEquals(raw)
            #expect(equal)
            try psk.encode(into: &encoded, encoding: encoding)
            let decodedPSK = try PresharedKey(parsing: encoded, encoding: encoding)
            try decodedPSK.encode(into: &roundTrip)
            let pskEqual = roundTrip.constantTimeEquals(raw)
            #expect(pskEqual)
        }
    }

    @Test
    func `invalid key lengths and buffers throw without clamping imported bytes`() throws {
        #expect(throws: KeyError.invalidLength(31)) { _ = try PrivateKey(bytes: SecretBytes(zeroedCount: 31)) }
        #expect(throws: KeyError.invalidLength(33)) { _ = try PresharedKey(bytes: SecretBytes(zeroedCount: 33)) }
        let key = try PrivateKey.generate()
        var wrong = try SecretBytes(zeroedCount: 31)
        #expect(throws: KeyError.invalidEncoding) { try key.encode(into: &wrong) }
        let raw = try Self.secret(Self.alice)
        let imported = try PrivateKey(parsing: raw)
        var exported = try SecretBytes(zeroedCount: 32)
        try imported.encode(into: &exported)
        let unchanged = raw.constantTimeEquals(exported)
        #expect(unchanged)
    }

    private static func secret(_ source: [UInt8]) throws -> SecretBytes {
        var result = try SecretBytes(zeroedCount: source.count)
        source.withUnsafeBytes { input in result.withUnsafeMutableBytes { $0.copyMemory(from: input) } }
        return result
    }

    private static func fixture(_ name: String) throws -> Data {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var file = try Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/" + name))
        defer { file.resetBytes(in: file.startIndex ..< file.endIndex) }
        let line = try #require(file.split(separator: 10).first { $0.first != 35 && !$0.isEmpty })
        return Data(line)
    }
}
