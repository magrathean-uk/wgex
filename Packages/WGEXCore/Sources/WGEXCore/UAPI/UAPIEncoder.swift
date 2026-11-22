// SPDX-License-Identifier: MIT
// Adapted from wireguard-apple Sources/WireGuardApp/Tunnel/TunnelConfiguration+UapiConfig.swift at 2fec12a6e1f6, MIT
import Foundation

public enum UAPIEncodingError: Error, Sendable, Hashable {
    case unresolvedEndpoint
    case invalidProfile
}

public enum UAPIEncoder {
    /// Full replacement, including an empty peer list. Resolve hostnames on the underlay
    /// before calling, supplying literal overrides without modifying the saved profile.
    public static func fullConfiguration(
        _ profile: TunnelProfile, secrets: borrowing ParsedSecrets, endpoints: [PublicKey: Endpoint] = [:],
    ) throws -> UAPIDocument {
        guard profile.peers.count <= 1024, Set(profile.peers.map(\.publicKey)).count == profile.peers.count,
              profile.peers.reduce(0, { $0 + $1.allowedIPs.count }) <= 4096
        else { throw UAPIEncodingError.invalidProfile }
        var builder = SecretDocumentBuilder()
        builder.append("private_key="); builder.appendKey(profile.secrets.privateKey, encoding: .hex)
        builder.append("\nlisten_port=\(profile.interface.listenPort ?? 0)\nreplace_peers=true\n")
        for peer in profile.peers {
            guard peer.hasPresharedKey == (profile.secrets.presharedKeys[peer.publicKey] != nil)
            else { throw UAPIEncodingError.invalidProfile }
            builder.append("public_key=\(hex(peer.publicKey))\n")
            if let reference = profile.secrets.presharedKeys[peer.publicKey] {
                builder.append("preshared_key="); builder.appendKey(reference, encoding: .hex); builder.append("\n")
            }
            if let endpoint = endpoints[peer.publicKey] ?? peer.endpoint {
                try validateLiteral(endpoint)
                builder.append("endpoint=\(endpoint.stringRepresentation)\n")
            }
            builder.append("persistent_keepalive_interval=\(peer.persistentKeepalive ?? 0)\nreplace_allowed_ips=true\n")
            for range in peer.allowedIPs {
                builder.append("allowed_ip=\(range.stringRepresentation)\n")
            }
        }
        return try UAPIDocument(bytes: builder.finish(secrets: secrets))
    }

    /// A partial document contains exactly the fields permitted by wgex_update_endpoints.
    public static func endpointUpdates(_ updates: [PublicKey: Endpoint]) throws -> UAPIDocument {
        guard updates.count <= 1024 else { throw UAPIEncodingError.invalidProfile }
        var text = ""
        for key in updates.keys.sorted(by: { $0.base64 < $1.base64 }) {
            if let endpoint = updates[key] {
                try validateLiteral(endpoint)
                text += "public_key=\(hex(key))\nupdate_only=true\nendpoint=\(endpoint.stringRepresentation)\n"
            }
        }
        var result: SecretBytes?
        try Array(text.utf8).withUnsafeBytes { result = try SecretBytes(copying: $0) }
        guard let bytes = consume result else { throw UAPIEncodingError.invalidProfile }
        return UAPIDocument(bytes: consume bytes)
    }

    private static func validateLiteral(_ endpoint: Endpoint) throws {
        try endpoint.validate()
        guard !endpoint.host.contains("/"), (try? IPAddressRange(endpoint.host)) != nil else { throw UAPIEncodingError.unresolvedEndpoint }
    }

    private static func hex(_ key: PublicKey) -> String {
        key.rawValue.map { String(format: "%02x", $0) }.joined()
    }
}
