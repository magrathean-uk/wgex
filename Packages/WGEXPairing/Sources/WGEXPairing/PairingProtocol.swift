// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import WGEXCore

public enum PairingError: Error, Sendable, Equatable {
    case invalidTransition, expired, attemptsExhausted, closed, cancelled
    case invalidQR, unsupportedVersion, invalidSessionID, invalidKey
    case malformedMessage, unexpectedMessage, frameOverflow, truncatedFrame
    case commitmentMismatch, authenticationFailed, sasMismatch, rejected
    case invalidProfile, overwriteRejected, storageFailed, networkUnavailable
}

public enum PairingMode: UInt8, Sendable { case qr = 1, manual = 2 }

/// Opaque scanner data. This API never opens or registers a URL scheme.
public struct PairingInvitation: Sendable, Equatable {
    public let sessionID: String
    public let publicKey: Data

    public init(sessionID: String, publicKey: Data) throws(PairingError) {
        guard Self.validID(sessionID) else { throw .invalidSessionID }
        guard publicKey.count == 32 else { throw .invalidKey }
        self.sessionID = sessionID; self.publicKey = publicKey
    }

    package static func validID(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

public enum PairingQRCodec {
    public static func encode(_ invitation: PairingInvitation) -> String {
        "wgex-pair://v1/\(invitation.sessionID)/\(base64URL(invitation.publicKey))"
    }

    public static func decode(_ scannedText: String) throws(PairingError) -> PairingInvitation {
        guard scannedText.utf8.count <= 128, scannedText.hasPrefix("wgex-pair://") else { throw .invalidQR }
        let parts = scannedText.dropFirst(12).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw .invalidQR }
        guard parts[0] == "v1" else { throw .unsupportedVersion }
        let encoded = String(parts[2])
        guard encoded.utf8.count == 43, encoded.utf8.allSatisfy({
                  (65 ... 90).contains($0) || (97 ... 122).contains($0) || (48 ... 57).contains($0) || $0 == 45 || $0 == 95
              }),
              let key = Data(base64Encoded: encoded.replacingOccurrences(of: "-", with: "+")
                  .replacingOccurrences(of: "_", with: "/") + "="),
              base64URL(key) == encoded else { throw .invalidKey }
        return try PairingInvitation(sessionID: String(parts[1]), publicKey: key)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Canonical binary messages: version, kind, then UInt32-length-prefixed fields.
/// Fields contain public handshake data or ciphertext, never plaintext profiles.
public struct PairingMessage: Sendable, Equatable {
    public enum Kind: UInt8, Sendable, CaseIterable {
        case hello = 1, commit, ack, reveal, sasConfirm, sealedProfile, result
    }

    public let kind: Kind
    public let fields: [Data]

    public init(_ kind: Kind, _ fields: [Data]) throws(PairingError) {
        self.kind = kind; self.fields = fields
        try validate()
    }

    public func encoded() throws(PairingError) -> Data {
        var data = Data([1, kind.rawValue])
        for field in fields {
            guard field.count <= PairingFrame.maximumLength else { throw .frameOverflow }
            data.append(PairingFrame.lengthBytes(field.count)); data.append(field)
        }
        guard data.count <= PairingFrame.maximumLength else { throw .frameOverflow }
        return data
    }

    public static func decode(_ data: Data) throws(PairingError) -> PairingMessage {
        guard data.count <= PairingFrame.maximumLength else { throw .frameOverflow }
        let bytes = Array(data)
        guard bytes.count >= 2 else { throw .malformedMessage }
        guard bytes[0] == 1 else { throw .unsupportedVersion }
        guard let kind = Kind(rawValue: bytes[1]) else { throw .malformedMessage }
        var cursor = 2; var fields: [Data] = []
        while cursor < bytes.count {
            guard fields.count < 4, bytes.count - cursor >= 4 else { throw .malformedMessage }
            let length = bytes[cursor ..< cursor + 4].reduce(0) { $0 << 8 | Int($1) }; cursor += 4
            guard length <= bytes.count - cursor else { throw .malformedMessage }
            fields.append(Data(bytes[cursor ..< cursor + length])); cursor += length
        }
        return try PairingMessage(kind, fields)
    }

    private func validate() throws(PairingError) {
        let sizes = fields.map(\.count)
        if kind == .hello {
            try validateHello(sizes)
        } else if kind == .ack {
            guard sizes.isEmpty || sizes == [32] else { throw .malformedMessage }
        } else if kind == .sealedProfile {
            guard sizes.count == 1, sizes[0] >= 16 else { throw .malformedMessage }
        } else {
            let expected: [Kind: [Int]] = [.commit: [36, 32], .reveal: [36, 32, 32], .sasConfirm: [1, 32], .result: [32]]
            guard sizes == expected[kind] else { throw .malformedMessage }
        }
        if kind == .sasConfirm, fields[0] != Data([1]) {
            throw .malformedMessage
        }
        try validateSessionID()
    }

    private func validateSessionID() throws(PairingError) {
        if kind == .commit || kind == .reveal {
            guard PairingInvitation.validID(String(decoding: fields[0], as: UTF8.self)) else { throw .invalidSessionID }
        }
        if kind == .hello, !fields[1].isEmpty {
            guard PairingInvitation.validID(String(decoding: fields[1], as: UTF8.self)) else { throw .invalidSessionID }
        }
    }

    private func validateHello(_ sizes: [Int]) throws(PairingError) {
        guard sizes.count == 3, sizes[0] == 1,
              let mode = fields[0].first.flatMap(PairingMode.init(rawValue:)),
              sizes[1] == (mode == .qr ? 36 : 0), sizes[2] == 32 else { throw .malformedMessage }
    }
}

public enum PairingFrame {
    public static let maximumLength = 64 * 1024
    /// The encrypted frame includes version, kind, field length and the AEAD tag.
    public static let maximumProfileLength = maximumLength - 6 - 16

    package static func lengthBytes(_ length: Int) -> Data {
        Data([
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ])
    }

    public static func encode(_ body: Data) throws(PairingError) -> Data {
        guard !body.isEmpty, body.count <= maximumLength else { throw .frameOverflow }
        return lengthBytes(body.count) + body
    }

    public static func decode(_ frame: Data) throws(PairingError) -> Data {
        guard frame.count >= 4 else { throw .truncatedFrame }
        let length = frame.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, length <= maximumLength else { throw .frameOverflow }
        guard frame.count == length + 4 else { throw .truncatedFrame }
        return Data(frame.dropFirst(4))
    }
}

package struct PairingTranscript: Sendable {
    private var hasher = SHA256()
    package var digest: Data {
        Data(hasher.finalize())
    }

    package mutating func append(_ message: PairingMessage) throws {
        try hasher.update(data: PairingFrame.encode(message.encoded()))
    }
}

package enum PairingCrypto {
    package static func info(sid: String, tv: Data, sender: Data) -> Data {
        Data("wgex-pair v1".utf8) + Data(sid.utf8) + tv + sender
    }

    package static func sasContext(_ transcript: Data) -> Data {
        Data("wgex-sas v1".utf8) + transcript
    }

    /// Interpret exporter bytes as a big-endian unsigned integer; left-pad decimal to 6 digits, take its first 6.
    package static func sas(_ key: SymmetricKey) -> String {
        let value = key.withUnsafeBytes { $0.reduce(UInt64(0)) { $0 << 8 | UInt64($1) } }
        let decimal = String(value)
        return String((String(repeating: "0", count: max(0, 6 - decimal.count)) + decimal).prefix(6))
    }

    package static func nonceCommitment(sid: String, key: Data, nonce: Data, role: String) -> Data {
        Data(SHA256.hash(data: Data("wgex-sas-commit v1".utf8) + Data(role.utf8) + Data(sid.utf8) + key + nonce))
    }

    package static func proof(_ key: SymmetricKey, role: String, transcript: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(role.utf8) + transcript, using: key))
    }

    package static func verify(_ proof: Data, key: SymmetricKey, role: String, transcript: Data) throws(PairingError) {
        guard HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: Data(role.utf8) + transcript, using: key)
        else { throw .authenticationFailed }
    }
}
