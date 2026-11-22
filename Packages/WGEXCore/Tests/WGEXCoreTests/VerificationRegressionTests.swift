// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Testing
import WGEXCore

private struct VerificationRegressionTests {
    /// Synthetic fixtures are generated here; assertions report booleans, never key values.
    private var shapes: [String] {
        let padded = Data(repeating: 0xFB, count: 32).base64EncodedString()
        return [
            padded,
            String(padded.dropLast()),
            String(padded.dropLast()).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"),
            String(repeating: "a7", count: 32),
        ]
    }

    @Test(arguments: ["name", "Endpoint", "DNS", "Address", "AllowedIPs", "ListenPort", "MTU", "PersistentKeepalive", "Bogus"])
    func `key material in every public parser field fails with a named diagnostic`(field: String) throws {
        for key in shapes {
            let value = field == "Endpoint" ? "\(key):51820" : key
            let peerField = ["Endpoint", "AllowedIPs", "PersistentKeepalive"].contains(field)
            var bytes = try Array(CodecFixtures.minimal(
                interface: field == "name" || peerField ? "" : "\(field)=\(value)",
                peer: peerField ? "\(field)=\(value)" : "",
            ).utf8)
            do {
                _ = try parseWgQuick(&bytes, name: field == "name" ? key : "Tunnel")
                Issue.record("Public key-shaped value was accepted")
            } catch let ConfigParseError.diagnostics(diagnostics) {
                #expect(diagnostics.first?.code == .invalidKey)
                #expect(diagnostics.first?.message == UserStrings.secretInPublicField)
            }
            #expect(bytes.allSatisfy { $0 == 0 })
        }
    }

    @Test(arguments: ["name", "endpoint", "searchDomain", "splitDNS", "alwaysSSID", "wifiSSID"])
    func `editor validation rejects key material in public profile strings`(field: String) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal().utf8))
        for key in shapes {
            var profile = parsed.profile
            switch field {
            case "name": profile.name = key
            case "endpoint":
                var endpoint = try Endpoint("vpn.example:1"); endpoint.host = key
                profile.peers[0].endpoint = endpoint
            case "searchDomain": profile.interface.searchDomains = [key]
            case "splitDNS": profile.protection.dnsPolicy = .split([key])
            case "alwaysSSID": profile.onDemand = .always(exceptSSIDs: [key])
            default: profile.onDemand = .wifiOnly(exceptSSIDs: [key])
            }
            #expect(profile.validate()
                .contains { $0.code == .invalidKey && $0.message == UserStrings.secretInPublicField && $0.severity == .error })
        }
    }

    @Test(arguments: ["127.1", "010.0.0.1", "::ffff:010.0.0.1", "::ffff:127.1"])
    func `all literal consumers reject historical IPv4 forms including IPv6 tails`(host: String) {
        let endpoint = host.contains(":") ? "[\(host)]:1" : "\(host):1"
        #expect(throws: ConfigurationError.self) { _ = try Endpoint(endpoint) }
        #expect(throws: ConfigurationError.self) { _ = try IPAddressRange(host + (host.contains(":") ? "/128" : "/32")) }
        #expect(Endpoint(validating: endpoint) == nil)
        let legacy = Endpoint(host: host, port: 1)
        #expect(throws: ConfigurationError.self) { try legacy.validate() }
    }

    @Test
    func `strict literals and hostname remain valid through every construction path`() throws {
        for host in ["127.0.0.1", "0.0.0.0", "::ffff:192.0.2.1", "::1", "vpn.example"] {
            let endpoint = try Endpoint(validatingHost: host, port: 1)
            #expect(try Endpoint(endpoint.stringRepresentation) == endpoint)
            #expect(Endpoint(validating: endpoint.stringRepresentation) == endpoint)
        }
    }

    @Test(arguments: [63, 64, 65])
    func `combined DNS cap agrees between editor and parser round trip`(count: Int) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal().utf8))
        var profile = parsed.profile
        profile.interface.dns = try [DNSServer("10.77.0.1")]
        profile.interface.searchDomains = Array(repeating: "corp.example", count: count - 1)
        #expect(profile.validate().contains { $0.code == .limitExceeded } == (count > 64))
        let text = try serialiseWgQuick(profile, secrets: parsed.secrets)
        var bytes = text.bytes.withUnsafeBytes { Array($0) }
        if count > 64 {
            #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes) }
        } else {
            let again = try parseWgQuick(&bytes)
            #expect(again.profile.interface == profile.interface)
        }
        profile.interface.dns = []
        profile.interface.searchDomains = Array(repeating: "corp.example", count: 65)
        #expect(profile.validate().contains { $0.code == .limitExceeded })
    }

    @Test(arguments: ["", "bad_domain", "-bad.example", "a..example", "192.0.2.999", "x\n.example"])
    func `search domain validation agrees with import`(domain: String) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal().utf8))
        var profile = parsed.profile; profile.interface.searchDomains = [domain]
        #expect(profile.validate().contains { $0.code == .invalidDNS })
        if !domain.contains("\n") {
            var bytes = try Array(CodecFixtures.minimal(interface: "DNS=\(domain)").utf8)
            #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes) }
        }
    }

    @Test(arguments: ["127.0.0.1", "::1"])
    func `editor search domains cannot silently become resolver addresses on round trip`(address: String) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal().utf8))
        var profile = parsed.profile; profile.interface.searchDomains = [address]
        #expect(profile.validate().contains { $0.code == .invalidDNS })
    }

    @Test(arguments: ["# literal $WGEX_SECRET:unterminated\n", "# literal $WGEX_SECRET:unterminated", "# $$\n"])
    func `malformed marker before a real placeholder cannot consume its opening delimiter`(literal: String) throws {
        // Prefix case occurs in genuine imports, before the parser inserts its first marker.
        let text = try literal + (literal.hasSuffix("\n") ? "" : "\n") + CodecFixtures.minimal()
        let parsed = try parseWgQuick(Array(text.utf8))
        let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        #expect(exported.bytes.withUnsafeBytes { $0.elementsEqual(text.utf8) })
        // Put a malformed literal immediately beside a real marker in a retained document.
        var adjacent = parsed.original
        adjacent.text = literal + parsed.profile.secrets.privateKey.placeholder
        let key = try CodecFixtures.key("client1.key")
        adjacent.sha256OfOriginal = Data(SHA256.hash(data: Data((literal + key).utf8)))
        let restored = try exportOriginalWgQuick(adjacent, secrets: parsed.secrets)
        #expect(restored.bytes.withUnsafeBytes { $0.elementsEqual((literal + key).utf8) })
    }

    @Test
    func `dense maximum sized input with 1024 preshared peers meets parser budget`() throws {
        var text = try "[Interface]\nPrivateKey=\(CodecFixtures.key("client1.key"))\nAddress=10.77.0.2/32\n"
        let psk = try CodecFixtures.key("psk1.key")
        for number in 0 ..< 1024 {
            var data = Data(repeating: 0, count: 32)
            data[0] = UInt8(truncatingIfNeeded: number); data[1] = UInt8(truncatingIfNeeded: number >> 8)
            text += "[Peer]\nPublicKey=\(data.base64EncodedString())\nPresharedKey=\(psk)\n"
        }
        var bytes = Array(text.utf8)
        bytes += [35, 36]
        bytes.append(contentsOf: repeatElement(46, count: 262_144 - bytes.count))
        let start = ContinuousClock.now
        let parsed = try parseWgQuick(bytes)
        let elapsed = start.duration(to: .now)
        #expect(parsed.profile.peers.count == 1024)
        #expect(parsed.secrets.references.count == 1025)
        #if DEBUG
            #expect(elapsed < .seconds(3))
        #else
            #expect(elapsed < .milliseconds(50))
        #endif
    }
}
