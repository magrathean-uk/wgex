// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDiagnostics
import WGEXPairing
import WGEXProfileStore
import WGEXTesting

package enum Oracles {
    /// Independent Foundation object walk; catches secret members in accepted documents.
    /// Explicit controls separately cover duplicate JSON keys which dictionaries overwrite.
    package static func containsSecretMember(_ bytes: [UInt8]) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: Data(bytes), options: [.fragmentsAllowed]) else { return false }
        return containsSecret(object)
    }

    private static func containsSecret(_ object: Any) -> Bool {
        if let dictionary = object as? [String: Any] {
            return dictionary.contains { key, value in
                ["private_key", "preshared_key"].contains(key.lowercased()) || containsSecret(value)
            }
        }
        if let array = object as? [Any] {
            return array.contains(where: containsSecret)
        }
        return false
    }

    /// Parsing may accept valid keys, but must capture them outside public original text.
    package static func parser(_ bytes: [UInt8], wiping: Bool) -> String {
        do {
            if wiping {
                var input = bytes
                let parsed = try parseWgQuick(&input)
                guard input.allSatisfy({ $0 == 0 }) else { return "input-not-wiped" }
                return try inspect(parsed)
            }
            let parsed = try parseWgQuick(bytes)
            return try inspect(parsed)
        } catch {
            // Decoder and parser error descriptions must not echo key-bearing input.
            return "rejected"
        }
    }

    private static func inspect(_ parsed: borrowing ParsedConfiguration) throws -> String {
        let text = parsed.original.text
        for reference in parsed.secrets.references.keys {
            let leaked = try parsed.secrets.withKey(reference) { raw in
                let base64 = Data(raw).base64EncodedString()
                let hex = raw.map { String(format: "%02x", $0) }.joined()
                return text.contains(base64) || text.lowercased().contains(hex)
            }
            if leaked {
                return "secret-in-public-original"
            }
        }
        return "accepted"
    }

    package static func stats(_ bytes: [UInt8], mustReject: Bool, referenceSecret: Bool) -> String {
        do {
            _ = try UAPIStatsDecoder.decode(bytes)
            return mustReject || referenceSecret ? "secret-key-accepted" : "accepted"
        } catch { return "rejected" }
    }

    /// Accepted imports must survive original export with identical public semantics and secrets.
    package static func original(_ bytes: [UInt8]) -> String {
        do {
            let parsed = try parseWgQuick(bytes)
            do {
                let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
                var result: ParsedConfiguration?
                try exported.bytes.withUnsafeBytes { raw in result = try parseWgQuick(Array(raw)) }
                guard let again = consume result else { return "roundtrip-failed" }
                let first = parsed.profile
                let second = again.profile
                // IDs, secret references and timestamps are allocated per import, not configuration semantics.
                let comparable = TunnelProfile(
                    id: first.id, name: second.name, interface: second.interface, peers: second.peers,
                    secrets: first.secrets, transport: first.transport, protection: second.protection,
                    onDemand: second.onDemand, macOptions: second.macOptions, original: first.original,
                    createdAt: first.createdAt, updatedAt: first.updatedAt,
                )
                guard first == comparable else { return "roundtrip-profile-mismatch" }
                let privateEqual = try parsed.secrets.withKey(first.secrets.privateKey) { lhs in
                    try again.secrets.withKey(second.secrets.privateKey) { lhs.elementsEqual($0) }
                }
                guard privateEqual else { return "roundtrip-secret-mismatch" }
                for (peer, reference) in first.secrets.presharedKeys {
                    guard let other = second.secrets.presharedKeys[peer] else { return "roundtrip-secret-mismatch" }
                    let equal = try parsed.secrets.withKey(reference) { lhs in
                        try again.secrets.withKey(other) { lhs.elementsEqual($0) }
                    }
                    guard equal else { return "roundtrip-secret-mismatch" }
                }
                return "accepted"
            } catch { return "roundtrip-failed" }
        } catch { return "rejected" }
    }

    package static func evaluate(_ target: String, bytes: [UInt8], registered: SecretScanner = SecretScanner()) -> String {
        do {
            switch target {
            case "endpoint":
                let value = try Endpoint(String(decoding: bytes, as: UTF8.self))
                return try Endpoint(value.stringRepresentation) == value ? "accepted" : "roundtrip-endpoint-mismatch"
            case "cidr":
                let value = try IPAddressRange(String(decoding: bytes, as: UTF8.self))
                return try IPAddressRange(value.stringRepresentation) == value ? "accepted" : "roundtrip-cidr-mismatch"
            case "original": return original(bytes)
            case "profile":
                let value = try JSONDecoder().decode(ProfileDocument.self, from: Data(bytes))
                return try JSONDecoder().decode(ProfileDocument.self, from: value.encoded(
                )) == value ? "accepted" : "roundtrip-profile-mismatch"
            case "pairing":
                let value = try PairingMessage.decode(Data(bytes))
                return try PairingMessage.decode(value.encoded()) == value ? "accepted" : "roundtrip-pairing-mismatch"
            case "qr":
                let value = try PairingQRCodec.decode(String(decoding: bytes, as: UTF8.self))
                return try PairingQRCodec.decode(PairingQRCodec.encode(value)) == value ? "accepted" : "roundtrip-qr-mismatch"
            case "redactor": return redactor(bytes, registered: registered)
            case "zip": return try archive(bytes)
            default: return "unknown-target"
            }
        } catch { return "rejected" }
    }

    /// Exact registration is an independent oracle even if key-shape recognition misses the input.
    package static func registeredKeyLeaked(_ output: String, scanner: SecretScanner) -> Bool {
        scanner.findings(in: output).contains { $0.kind == .registeredSecret }
    }

    private static func redactor(_ bytes: [UInt8], registered: SecretScanner) -> String {
        let rawText = String(decoding: bytes, as: UTF8.self)
        let shaped = bytes.withUnsafeBytes { KeyShape.matches(in: $0, wholeTokens: true) }
        if !shaped.isEmpty, SecretScanner().isClean(rawText) {
            return "scanner-key-missed"
        }
        let result = Redactor().redact(rawText)
        if registeredKeyLeaked(result, scanner: registered) {
            return "redactor-registered-key-leak"
        }
        return SecretScanner().isClean(result) ? "accepted" : "redactor-key-leak"
    }

    private static func archive(_ bytes: [UInt8]) throws -> String {
        let entries = try ZipArchiveReader.archive(Data(bytes))
        guard entries.count <= 64, entries.allSatisfy({ $0.1.count <= ParseLimits.default.maximumBytes }),
              entries.reduce(0, { $0 + $1.1.count }) <= ZipArchiveReader.maximumBytes else { return "zip-limit-bypass" }
        return "accepted"
    }
}
