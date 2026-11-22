// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Creates an isolated full-tunnel example without bundled key material.
public enum GeneratedFixture {
    /// Each call generates independent interface and peer keypairs. The caller must wipe the returned bytes.
    public static func configurationBytes() throws -> [UInt8] {
        let key = try PrivateKey.generate()
        _ = try key.publicKey()
        let peer = try PrivateKey.generate()
        let publicKey = try peer.publicKey()
        let prefix = "[Interface]\nPrivateKey = "
        let suffix = """

        Address = 192.0.2.2/32, 2001:db8::2/128
        DNS = 192.0.2.53
        [Peer]
        PublicKey = \(publicKey.base64)
        Endpoint = vpn.example.invalid:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        """
        var encoded = try SecretBytes(zeroedCount: 44)
        try key.encode(into: &encoded, encoding: .base64)
        var bytes = Array(prefix.utf8)
        encoded.withUnsafeBytes { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: suffix.utf8)
        return bytes
    }
}
