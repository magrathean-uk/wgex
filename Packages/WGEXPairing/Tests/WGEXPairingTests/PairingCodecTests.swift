// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Network
import Testing
@testable import WGEXPairing

private struct PairingCodecTests {
    private let sid = "12345678-1234-1234-1234-123456789abc"
    private var invitation: PairingInvitation {
        get throws { try PairingInvitation(sessionID: sid, publicKey: Data(0 ..< 32)) }
    }

    @Test
    func `QR is canonical opaque scanner data`() throws {
        let value = try invitation
        #expect(try PairingQRCodec.decode(PairingQRCodec.encode(value)) == value)
        #expect(throws: PairingError.invalidSessionID) { _ = try PairingInvitation(sessionID: sid.uppercased(), publicKey: Data(0 ..< 32)) }
        #expect(throws: PairingError.invalidKey) { _ = try PairingInvitation(sessionID: sid, publicKey: Data()) }
    }

    @Test(arguments: ["https://v1/", "wgex-pair://v2/", "wgex-pair://v1", "WGEX-PAIR://v1/", "wgex-pair://v1//", "wgex-pair://v1/user@"])
    func `QR rejects schemes versions and malformed paths`(prefix: String) throws {
        let value = try invitation
        let canonical = PairingQRCodec.encode(value)
        let suffix = canonical.dropFirst("wgex-pair://v1/".count)
        #expect(throws: PairingError.self) { _ = try PairingQRCodec.decode(prefix + suffix) }
    }

    @Test(arguments: ["/", "?q=x", "#fragment", "=", "%00", "\n", "/extra"])
    func `QR rejects suffixes padding escaping and controls`(suffix: String) throws {
        let canonical = try PairingQRCodec.encode(invitation)
        #expect(throws: PairingError.self) { _ = try PairingQRCodec.decode(canonical + suffix) }
    }

    @Test
    func `QR rejects invalid sid key length alphabet and noncanonical tail bits`() throws {
        let prefix = "wgex-pair://v1/\(sid)/"
        for key in [
            "",
            String(repeating: "A", count: 42),
            String(repeating: "A", count: 44),
            String(repeating: "A", count: 42) + "+",
            String(repeating: "A", count: 42) + "B",
        ] {
            #expect(throws: PairingError.invalidKey) { _ = try PairingQRCodec.decode(prefix + key) }
        }
        #expect(throws: PairingError.invalidSessionID) {
            _ = try PairingQRCodec.decode(prefix.replacingOccurrences(of: sid, with: "bad") + String(
                repeating: "A",
                count: 43,
            ))
        }
    }

    @Test
    func `every message kind round trips and transcript includes order and frame length`() throws {
        let messages = try [
            PairingMessage(.hello, [Data([2]), Data(), Data(repeating: 1, count: 32)]),
            PairingMessage(.commit, [Data(sid.utf8), Data(repeating: 2, count: 32)]),
            PairingMessage(.ack, []), PairingMessage(.ack, [Data(repeating: 3, count: 32)]),
            PairingMessage(.reveal, [Data(sid.utf8), Data(repeating: 4, count: 32), Data(repeating: 5, count: 32)]),
            PairingMessage(.sasConfirm, [Data([1]), Data(repeating: 6, count: 32)]),
            PairingMessage(.sealedProfile, [Data(repeating: 7, count: 16)]), PairingMessage(.result, [Data(repeating: 8, count: 32)]),
        ]
        var transcript = PairingTranscript(); var bytes = Data()
        for message in messages {
            let encoded = try message.encoded()
            #expect(try PairingMessage.decode(encoded) == message)
            try transcript.append(message); try bytes.append(PairingFrame.encode(encoded))
        }
        #expect(transcript.digest == Data(SHA256.hash(data: bytes)))
        var reverse = PairingTranscript()
        for message in messages.reversed() {
            try reverse.append(message)
        }
        #expect(transcript.digest != reverse.digest)
    }

    @Test(arguments: PairingMessage.Kind.allCases)
    func `message rejects missing fields`(kind: PairingMessage.Kind) {
        if kind != .ack {
            #expect(throws: PairingError.malformedMessage) { _ = try PairingMessage(kind, []) }
        }
    }

    @Test
    func `wire rejects unsupported version unknown tags extra fields and truncation`() throws {
        #expect(throws: PairingError.unsupportedVersion) { _ = try PairingMessage.decode(Data([2, 3])) }
        #expect(throws: PairingError.malformedMessage) { _ = try PairingMessage.decode(Data([1, 255])) }
        #expect(throws: PairingError.malformedMessage) { _ = try PairingMessage.decode(Data([1, 3, 0, 0, 0, 1])) }
        let valid = try PairingMessage(.ack, []).encoded()
        #expect(throws: PairingError.malformedMessage) { _ = try PairingMessage.decode(valid + Data(repeating: 0, count: 20)) }
        #expect(throws: PairingError.malformedMessage) { _ = try PairingMessage(.sasConfirm, [Data([0]), Data(repeating: 0, count: 32)]) }
        for length in 0 ..< 6 {
            #expect(throws: PairingError.self) { _ = try PairingFrame.decode(Data(repeating: 0, count: length)) }
        }
    }

    @Test(arguments: [65535, 65536, 65537])
    func `frame cap boundary and overflow closes endpoint`(length: Int) async throws {
        let body = Data(repeating: 42, count: length)
        let (first, second) = InMemoryPairingTransport.pair()
        if length <= 65536 {
            #expect(try PairingFrame.decode(PairingFrame.encode(body)) == body)
            try await first.send(body); #expect(try await second.receive() == body)
        } else {
            await expectPairingError(.frameOverflow) { try await first.send(body) }
            await expectPairingError(.closed) { try await first.send(Data([1])) }
            await expectPairingError(.closed) { _ = try await second.receive() }
        }
        await first.close()
    }

    @Test
    func `SAS decimal rendering preserves leading zeroes and exact prefix`() {
        #expect(PairingCrypto.sas(SymmetricKey(data: Data(repeating: 0, count: 8))) == "000000")
        #expect(PairingCrypto.sas(SymmetricKey(data: Data([0, 0, 0, 0, 0, 0, 0, 42]))) == "000042")
        #expect(PairingCrypto.sas(SymmetricKey(data: Data(repeating: 255, count: 8))) == "184467")
    }

    @Test
    func `HPKE exporter info aad and transcript bind both contexts`() throws {
        let key = Curve25519.KeyAgreement.PrivateKey(); let senderKey = Data(repeating: 2, count: 32)
        let info = PairingCrypto.info(sid: sid, tv: key.publicKey.rawRepresentation, sender: senderKey)
        #expect(info == Data("wgex-pair v1".utf8) + Data(sid.utf8) + key.publicKey.rawRepresentation + senderKey)
        var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: info)
        var recipient = try HPKE.Recipient(
            privateKey: key,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: info,
            encapsulatedKey: sender.encapsulatedKey,
        )
        let context = PairingCrypto.sasContext(Data([1, 2, 3]))
        let left = try sender.exportSecret(context: context, outputByteCount: 8)
        let right = try recipient.exportSecret(context: context, outputByteCount: 8)
        #expect(left == right)
        #expect(try sender.exportSecret(context: context + Data([4]), outputByteCount: 8) != left)
        let ciphertext = try sender.seal(Data([42]), authenticating: Data(sid.utf8))
        #expect(throws: (any Error).self) { _ = try recipient.open(ciphertext, authenticating: Data("wrong".utf8)) }
        var wrong = try HPKE.Recipient(
            privateKey: key,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: info + Data([0]),
            encapsulatedKey: sender.encapsulatedKey,
        )
        #expect(try wrong.exportSecret(context: context, outputByteCount: 8) != left)
        #expect(throws: (any Error).self) { _ = try wrong.open(ciphertext, authenticating: Data(sid.utf8)) }
    }

    @Test
    func `Bonjour metadata accepts only v equals one and carries no sid`() {
        #expect(PairingBonjourMetadata.accepts(NWTXTRecord(["v": "1"])))
        #expect(!PairingBonjourMetadata.accepts(NWTXTRecord(["v": "1", "sid": sid])))
        #expect(!PairingBonjourMetadata.accepts(NWTXTRecord(["v": "2"])))
        #expect(!PairingBonjourMetadata.accepts(NWTXTRecord()))
    }
}
