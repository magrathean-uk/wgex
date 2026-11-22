// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct M114HardeningTests {
    @Test(arguments: ["0x7f000001:80", "host.123:80", "host.0Xff:80", "host.123.:80"])
    func `numeric hostnames are rejected`(_ text: String) {
        #expect(throws: ConfigurationError.invalidEndpoint) { try Endpoint(text) }
    }

    @Test
    func `stats accept zoned IPv6`() throws {
        let key = try CodecFixtures.key("server.pub")
        let json = "{\"sampled_at\":123,\"peers\":[{\"public_key\":\"\(key)\",\"endpoint\":\"[fe80::1%en0]:51820\",\"rx_bytes\":7,\"tx_bytes\":9}]}"
        let stats = try UAPIStatsDecoder.decode(Array(json.utf8))
        #expect(stats.peers.first?.endpoint?.host == "fe80::1")
        #expect(stats.peers.first?.rxBytes == 7)
    }

    @Test
    func `public keys reject noncanonical padding`() throws {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
        var bytes = try Array(CodecFixtures.key("server.pub").utf8)
        let last = try #require(alphabet.firstIndex(of: bytes[42]))
        bytes[42] = alphabet[last | 1]
        let rejected = (try? PublicKey(base64: String(decoding: bytes, as: UTF8.self))) == nil
        #expect(rejected)
    }

    @Test
    func `repeated lists accumulate`() throws {
        let text = try CodecFixtures.minimal(
            interface: "Address=fd77::2/128\nDNS=10.77.0.1\nDNS=corp.example",
            peer: "AllowedIPs=fd77::/64",
        )
        let parsed = try parseWgQuick(Array(text.utf8))
        #expect(parsed.profile.interface.addresses.count == 2)
        #expect(parsed.profile.interface.dns.count == 1)
        #expect(parsed.profile.interface.searchDomains == ["corp.example"])
        #expect(parsed.profile.peers.first?.allowedIPs.count == 2)
    }

    @Test(arguments: ["Table", "FwMark", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown"])
    func `unsupported settings warn`(_ key: String) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal(interface: "\(key)=fixture").utf8))
        #expect(parsed.diagnostics.contains { $0.severity == .warning && $0.message == "ignored: not supported on Apple platforms" })
    }

    @Test
    func `allowed cap precedes invalid CIDR`() throws {
        let limits = try ParseLimits(
            maximumBytes: 262_144,
            maximumLines: 4096,
            maximumPeers: 1024,
            maximumAllowedIPs: 1,
            maximumDNS: 64,
            maximumNameCharacters: 128,
        )
        let text = try CodecFixtures.minimal().replacingOccurrences(of: "10.77.0.0/24", with: "invalid,invalid")
        do { _ = try parseWgQuick(Array(text.utf8), limits: limits); Issue.record("Expected limit rejection") }
        catch let ConfigParseError.diagnostics(values) { #expect(values.first?.code == .limitExceeded) }
    }

    @Test
    func `public byte range input rejects invalid lengths and prefixes`() throws {
        for count in [0, 3, 5, 15, 17] {
            #expect(throws: ConfigurationError.invalidCIDR) {
                try IPAddressRange(validatingBytes: Array(repeating: 0, count: count), prefixLength: 0)
            }
        }
        for prefix in [-1, 33] {
            #expect(throws: ConfigurationError.invalidCIDR) {
                try IPAddressRange(validatingBytes: [192, 0, 2, 7], prefixLength: prefix)
            }
        }
        #expect(try IPAddressRange(validatingBytes: [192, 0, 2, 7], prefixLength: 24) == IPAddressRange("192.0.2.7/24"))
    }

    @Test
    func `shared key shapes recognise all encodings`() throws {
        let key = try CodecFixtures.key("server.pub")
        let data = try #require(Data(base64Encoded: key))
        let unpadded = String(key.dropLast())
        let url = unpadded.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = data.map { String(format: "%02x", $0) }.joined()
        for token in [key, unpadded, url, url + "=", hex] {
            let bytes = Array(("x=" + token).utf8)
            #expect(KeyShape.contains(in: bytes))
            let spans = bytes.withUnsafeBytes { KeyShape.matches(in: $0, wholeTokens: true) }
            #expect(spans.count == 1)
            #expect(spans.first?.range == 2 ..< bytes.count)
        }
    }

    @Test(arguments: [
        "interop-repeated-address",
        "interop-repeated-dns",
        "interop-repeated-allowedips",
        "interop-ignored-table",
        "interop-ignored-fwmark",
        "interop-ignored-saveconfig",
        "interop-ignored-preup",
        "interop-ignored-postup",
        "interop-ignored-predown",
        "interop-ignored-postdown",
    ])
    func `interop fixtures import`(_ name: String) throws {
        let parsed = try parseWgQuick(CodecFixtures.conf(name))
        #expect(!parsed.diagnostics.contains { $0.severity == .error })
    }

    @Test
    func `legacy tunnel error text is discarded`() throws {
        let legacy = Data(#"{"invalidConfiguration":{"_0":"untrusted legacy text"}}"#.utf8)
        let error = try JSONDecoder().decode(TunnelError.self, from: legacy)
        let encoded = try JSONEncoder().encode(error)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("untrusted legacy text"))
        let legacyDecoded = try JSONDecoder().decode(LegacyTunnelError.self, from: encoded)
        switch legacyDecoded {
        case let .invalidConfiguration(reason): #expect(reason == "invalidProfile")
        }
    }

    @Test(arguments: [1279, 1280, 1500, 1501])
    func `apple MTU bounds`(_ mtu: Int) throws {
        let text = try CodecFixtures.minimal(interface: "MTU=\(mtu)")
        let accepted = (try? parseWgQuick(Array(text.utf8))) != nil
        #expect(accepted == (1280 ... 1500).contains(mtu))
    }
}

/// The previous client representation, retained only to prove the wire contract.
private enum LegacyTunnelError: Codable {
    case invalidConfiguration(String)
}
