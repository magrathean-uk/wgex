// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Testing
import WGEXCore

private enum RedactionVector: String, CaseIterable, Sendable {
    case commentedPrivateKey, trailingPresharedKey, hex, uppercaseHex, base64url, base64Symbols
    case commentedPublicKey, adjacentTokens, ordinaryComment, unpaddedBase64Symbols

    func comment() throws -> String {
        let key = try CodecFixtures.key("psk1.key")
        switch self {
        case .commentedPrivateKey: return try "# PrivateKey = \(CodecFixtures.key("server.key"))"
        case .trailingPresharedKey: return "# PresharedKey = \(key)"
        case .hex, .uppercaseHex:
            let data = try #require(Data(base64Encoded: key))
            let hex = data.map { String(format: "%02x", $0) }.joined()
            return "# hex = \(self == .hex ? hex : hex.uppercased())"
        case .base64url:
            return "# url = \(Self.symbolKey.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").dropLast())"
        case .base64Symbols: return "# base64 = \(Self.symbolKey)"
        case .unpaddedBase64Symbols: return "# unpadded = \(Self.symbolKey.dropLast())"
        case .commentedPublicKey: return try "# PublicKey = \(CodecFixtures.key("client1.pub"))"
        case .adjacentTokens: return "# (\(key)):\(key)"
        case .ordinaryComment: return "# ordinary comment; keep spacing and punctuation"
        }
    }

    private static var symbolKey: String {
        Data(repeating: 0xFB, count: 32).base64EncodedString()
    }
}

private struct WgQuickRedactionTests {
    @Test(arguments: RedactionVector.allCases)
    func `unparsed key shapes are irreversibly redacted and exports report alteration`(vector: RedactionVector) throws {
        let comment = try vector.comment()
        let minimal = try CodecFixtures.minimal()
        let privateLine = try "PrivateKey = \(CodecFixtures.key("client1.key"))"
        let text = vector == .trailingPresharedKey
            ? minimal.replacingOccurrences(of: privateLine, with: privateLine + "  " + comment)
            : minimal + comment // deliberately no final newline
        var input = Array(text.utf8)
        let parsed = try parseWgQuick(&input)
        #expect(input.allSatisfy { $0 == 0 })
        try expectNoFixtureSecrets(parsed.original)
        let redacted = vector != .ordinaryComment
        #expect(parsed.original.wasRedacted == redacted)
        #expect(parsed.original.text.contains("$WGEX_REDACTED$") == redacted)
        #expect(parsed.profile.original == parsed.original)
        let publicKeyPreserved = try parsed.original.text.contains(CodecFixtures.key("server.pub"))
        #expect(publicKeyPreserved)
        let expectedComment = redacted ? comment.replacingOccurrences(
            of: #"[0-9a-fA-F]{64}|[A-Za-z0-9+/]{43}=?|[A-Za-z0-9_-]{43}"#,
            with: "$WGEX_REDACTED$",
            options: .regularExpression,
        ) : comment
        let expected = vector == .trailingPresharedKey
            ? minimal.replacingOccurrences(of: privateLine, with: privateLine + "  " + expectedComment)
            : minimal + expectedComment
        let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        let matches = exported.bytes.withUnsafeBytes { $0.elementsEqual(expected.utf8) }
        #expect(matches)
        let byteIdentical = exported.bytes.withUnsafeBytes { $0.elementsEqual(text.utf8) }
        #expect(byteIdentical == !redacted)
        let decoded = try JSONDecoder().decode(OriginalText.self, from: JSONEncoder().encode(parsed.original))
        #expect(decoded == parsed.original)
        #expect(decoded.wasRedacted == redacted)
        var roundTrip = exported.bytes.withUnsafeBytes { Array($0) }
        let again = try parseWgQuick(&roundTrip)
        #expect(again.profile.interface == parsed.profile.interface)
        #expect(again.profile.peers == parsed.profile.peers)
    }

    @Test
    func `saved fuzz reproducer keeps secrets out of public original and exports safely`() throws {
        let path = CodecFixtures.root.appendingPathComponent(
            "Tests/Fixtures/fuzz/reproducers/parser-secret-in-public-original-s7-i904.bin",
        )
        var input = try Array(Data(contentsOf: path))
        #expect(input.count == 263)
        let originalHash = Data(SHA256.hash(data: Data(input)))
        let parsed = try parseWgQuick(&input)
        #expect(input.allSatisfy { $0 == 0 })
        try expectNoFixtureSecrets(parsed.original)
        #expect(parsed.original.wasRedacted)
        #expect(parsed.original.sha256OfOriginal == originalHash)
        #expect(parsed.original.text.components(separatedBy: "$WGEX_REDACTED$").count == 2)
        let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        var bytes = exported.bytes.withUnsafeBytes { Array($0) }
        let again = try parseWgQuick(&bytes)
        #expect(again.profile.interface == parsed.profile.interface)
        #expect(!again.original.wasRedacted)
        try expectNoFixtureSecrets(again.original)
    }

    @Test(arguments: ["Bogus", "PrivateKey", "not a pair"])
    func `unknown duplicate and rejected lines never return retained text`(field: String) throws {
        let secret = try CodecFixtures.key("server.key")
        var input = try Array(CodecFixtures.minimal(interface: "\(field) = \(secret)").utf8)
        var rejected = false
        do { _ = try parseWgQuick(&input) }
        catch { rejected = true }
        #expect(rejected)
        #expect(input.allSatisfy { $0 == 0 })
    }

    @Test
    func `redacted export still rejects edits and missing secrets`() throws {
        var input = try Array((CodecFixtures.minimal() + RedactionVector.commentedPrivateKey.comment()).utf8)
        let parsed = try parseWgQuick(&input)
        var edited = parsed.original; edited.text += "# edit\n"
        #expect(throws: ConfigurationError.invalidSecretReference) { _ = try exportOriginalWgQuick(edited, secrets: parsed.secrets) }
        let empty = try ParsedSecrets(bytes: SecretBytes(zeroedCount: 0), references: [:])
        #expect(throws: ConfigurationError.invalidSecretReference) {
            _ = try exportOriginalWgQuick(parsed.original, secrets: empty)
        }
    }

    @Test
    func `legacy original text decodes without redaction metadata`() throws {
        let legacy = ##"{"text":"# safe","sha256OfOriginal":"AA=="}"##
        let decoded = try JSONDecoder().decode(OriginalText.self, from: Data(legacy.utf8))
        #expect(!decoded.wasRedacted)
        #expect(decoded.sha256OfRedactedOriginal == nil)
        #expect(decoded == OriginalText(text: "# safe", sha256OfOriginal: Data([0])))
    }

    private func expectNoFixtureSecrets(_ original: OriginalText) throws {
        let leaked = try CodecFixtures.containsFixtureSecret(original.text)
        #expect(!leaked)
    }
}
