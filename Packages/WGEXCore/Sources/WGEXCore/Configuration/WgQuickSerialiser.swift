// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift at a27bce1b6f25, MIT
// Adapted from wireguard-apple Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift at 2fec12a6e1f6, MIT
import CryptoKit
import Foundation

/// Normalised public export. Secret references remain as placeholders.
public func serialiseWgQuick(_ profile: TunnelProfile) -> String {
    var output = "[Interface]\nPrivateKey = \(profile.secrets.privateKey.placeholder)\n"
    if !profile.interface.addresses.isEmpty {
        output += "Address = \(profile.interface.addresses.map(\.stringRepresentation).joined(separator: ", "))\n"
    }
    let dns = profile.interface.dns.map(\.stringRepresentation) + profile.interface.searchDomains
    if !dns.isEmpty {
        output += "DNS = \(dns.joined(separator: ", "))\n"
    }
    if let port = profile.interface.listenPort {
        output += "ListenPort = \(port)\n"
    }
    if let mtu = profile.interface.mtu {
        output += "MTU = \(mtu)\n"
    }
    if !profile.exclusions.isEmpty {
        output += "# \(TunnelExclusions.wgQuickKey) = \(profile.exclusions.entries.map(\.text).joined(separator: ", "))\n"
    }
    for peer in profile.peers {
        output += "\n[Peer]\nPublicKey = \(peer.publicKey.base64)\n"
        if let reference = profile.secrets.presharedKeys[peer.publicKey] {
            output += "PresharedKey = \(reference.placeholder)\n"
        }
        if !peer.allowedIPs.isEmpty {
            output += "AllowedIPs = \(peer.allowedIPs.map(\.stringRepresentation).joined(separator: ", "))\n"
        }
        if let endpoint = peer.endpoint {
            output += "Endpoint = \(endpoint.stringRepresentation)\n"
        }
        if let keepalive = peer.persistentKeepalive {
            output += "PersistentKeepalive = \(keepalive)\n"
        }
    }
    return output
}

/// Allocation and missing-key failures throw; no partial output escapes.
public func serialiseWgQuick(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets) throws -> SecretText {
    try restoreWgQuickText(serialiseWgQuick(profile), secrets: secrets)
}

/// Restores the retained import bytes, including BOM, comments, spacing and line endings.
/// Export the original only while the profile is unedited; use normalised export after edits.
/// When original.wasRedacted is true, unparsed key-shaped tokens and ignored directive values remain irreversibly redacted.
public func exportOriginalWgQuick(_ original: OriginalText, secrets: borrowing ParsedSecrets) throws -> SecretText {
    let restored = try restoreWgQuickText(original.text, secrets: secrets, preserveLiteralMarkers: true)
    let hash = restored.bytes.withUnsafeBytes { raw in
        var hasher = SHA256(); hasher.update(bufferPointer: raw)
        return Data(hasher.finalize())
    }
    guard hash == (original.sha256OfRedactedOriginal ?? original.sha256OfOriginal) else {
        throw ConfigurationError.invalidSecretReference
    }
    return restored
}

private func restoreWgQuickText(
    _ text: String, secrets: borrowing ParsedSecrets, preserveLiteralMarkers: Bool = false,
) throws -> SecretText {
    let markers = Dictionary(uniqueKeysWithValues: secrets.references.keys.map { ($0.placeholder, $0) })
    var builder = SecretDocumentBuilder()
    let bytes = Array(text.utf8)
    let ranges = bytes.withUnsafeBytes { SecretPlaceholder.ranges(in: $0) }
    var cursor = 0
    for range in ranges {
        // Two valid candidates can share a delimiter; the first complete marker owns it.
        guard range.lowerBound >= cursor else { continue }
        let marker = String(decoding: bytes[range], as: UTF8.self)
        guard let reference = markers[marker] else {
            if preserveLiteralMarkers {
                continue
            }
            throw ConfigurationError.invalidSecretReference
        }
        builder.append(String(decoding: bytes[cursor ..< range.lowerBound], as: UTF8.self))
        builder.appendKey(reference, encoding: .base64)
        cursor = range.upperBound
    }
    builder.append(String(decoding: bytes[cursor...], as: UTF8.self))
    return try SecretText(bytes: builder.finish(secrets: secrets))
}
