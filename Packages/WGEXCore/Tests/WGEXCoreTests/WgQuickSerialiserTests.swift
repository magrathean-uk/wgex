// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Tests/TunnelCoreTests/WgQuickTests.swift at a27bce1b6f25, MIT
import Foundation
import Testing
import WGEXCore

private struct WgQuickSerialiserTests {
    @Test(arguments: [
        "single-peer-full-tunnel",
        "multi-peer-split",
        "ipv6-dual-stack",
        "crlf-bom",
        "comments-and-whitespace",
        "server-two-peers",
    ])
    func `every accepted fixture exports byte identical original and normalised round trip`(name: String) throws {
        let fixture = try CodecFixtures.conf(name)
        var input = fixture
        let parsed = try parseWgQuick(&input)
        #expect(!parsed.original.wasRedacted)
        let lossless = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        let equal = lossless.bytes.withUnsafeBytes { $0.elementsEqual(fixture) }
        #expect(equal)
        let normalised = try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
        // Tests use throwaway fixtures; the production API never makes this array copy.
        var exported = normalised.bytes.withUnsafeBytes { Array($0) }
        let again = try parseWgQuick(&exported)
        #expect(again.profile.interface == parsed.profile.interface)
        #expect(again.profile.peers == parsed.profile.peers)
        let publicText = serialiseWgQuick(parsed.profile)
        #expect(publicText.contains("$WGEX_SECRET:"))
        let publicExportLeaked = try CodecFixtures.containsFixtureSecret(publicText)
        let originalLeaked = try CodecFixtures.containsFixtureSecret(parsed.original.text)
        #expect(!publicExportLeaked)
        #expect(!originalLeaked)
    }

    @Test
    func `adapted Wombat full configuration preserves DNS search keepalive PSK and derived public key`() throws {
        let text = try CodecFixtures.minimal(
            interface: "DNS=10.77.0.1,fd77::1,CORP.EXAMPLE\nMTU=1420",
            peer: "PresharedKey=\(CodecFixtures.key("psk1.key"))\nEndpoint=vpn.example.test:51820\nPersistentKeepalive=25",
        )
        .replacingOccurrences(of: "10.77.0.2/32", with: "10.77.0.2/32,fd77::2/128")
        .replacingOccurrences(of: "AllowedIPs = 10.77.0.0/24", with: "AllowedIPs = 0.0.0.0/0, ::/0")
        let parsed = try parseWgQuick(Array(text.utf8))
        #expect(try parsed.profile.interface.publicKey.base64 == (CodecFixtures.key("client1.pub")))
        #expect(parsed.profile.interface.addresses.count == 2)
        #expect(parsed.profile.interface.dns.count == 2)
        #expect(parsed.profile.interface.searchDomains == ["corp.example"])
        #expect(parsed.profile.interface.mtu == 1420)
        #expect(parsed.profile.peers[0].hasPresharedKey)
        #expect(parsed.profile.peers[0].allowedIPs.count == 2)
        #expect(parsed.profile.peers[0].endpoint?.host == "vpn.example.test")
        #expect(parsed.profile.peers[0].persistentKeepalive == 25)
        #expect(parsed.diagnostics.isEmpty)
    }

    @Test
    func `literal markers in comments survive and missing original keys fail closed`() throws {
        let text = try CodecFixtures.minimal() + "# literal $WGEX_SECRET:unrelated$ and $WGEX_SECRET:unterminated\n"
        let parsed = try parseWgQuick(Array(text.utf8))
        let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        let matches = exported.bytes.withUnsafeBytes { $0.elementsEqual(text.utf8) }
        #expect(matches)
        let empty = try ParsedSecrets(bytes: SecretBytes(zeroedCount: 0), references: [:])
        #expect(throws: ConfigurationError.invalidSecretReference) { _ = try exportOriginalWgQuick(parsed.original, secrets: empty) }
        var changed = parsed.original; changed.text += "# edit\n"
        #expect(throws: ConfigurationError.invalidSecretReference) { _ = try exportOriginalWgQuick(changed, secrets: parsed.secrets) }
    }

    @Test
    func `missing keys throw and partial secret output is discarded`() throws {
        let parsed = try parseWgQuick(CodecFixtures.conf("single-peer-full-tunnel"))
        let empty = try ParsedSecrets(bytes: SecretBytes(zeroedCount: 0), references: [:])
        #expect(throws: ConfigurationError.invalidSecretReference) { _ = try serialiseWgQuick(parsed.profile, secrets: empty) }
    }
}
