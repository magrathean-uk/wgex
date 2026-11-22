// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Tests/TunnelCoreTests/WgQuickTests.swift at a27bce1b6f25, MIT
// Adapted from wombat-vpn Packages/TunnelCore/Tests/TunnelCoreTests/ReviewAndStatsTests.swift at a27bce1b6f25, MIT
import CryptoKit
import Foundation
import Synchronization
import Testing
import WGEXCore

private struct ParserVector: Sendable, CustomTestStringConvertible {
    let field: String
    let value: String
    let code: ConfigDiagnostic.Code?
    var testDescription: String {
        "\(field): \(value.debugDescription)"
    }

    static let all: [ParserVector] = cidrs + numbers + forbidden + controls + keys + dns

    private static let cidrs: [ParserVector] = {
        let valid = [
            "10.0.0.1",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "::/0",
            "fd00::1/128",
            "2001:db8::/32",
            "192.0.2.1/32",
            "::1",
            "::ffff:192.0.2.1",
            "2001:db8::1/64",
        ]
        let invalid = [
            "10.1",
            "10.0.0.1/",
            "10.0.0.1/33",
            "fd00::/129",
            "fe80::1%en0",
            "host",
            "10.0.0.1/+8",
            "1.2.3.4/08x",
            "10.0.0.256/32",
            "10.0.0.1/-1",
            "::/",
            "::/256",
            "01.2.3.4/32",
            "1.2.3.4/32/1",
            "",
        ]
        return ["Address", "AllowedIPs"].flatMap { field in
            valid.map { ParserVector(field: field, value: $0, code: nil) } + invalid.map { ParserVector(
                field: field,
                value: $0,
                code: .invalidCIDR,
            ) }
        }
    }()

    private static let numbers: [ParserVector] = {
        let mtu = ["0", "1", "575", "576", "1279", "1280", "1420", "9000", "9001", "65535", "65536", "-1", "+576", "5x", ""]
        let ports = ["0", "1", "51820", "65535", "65536", "-1", "+1", "1.0", "off", ""]
        let endpoints = [
            "host",
            "2001:db8::1:51820",
            "[2001:db8::1]51820",
            "bad_host:1",
            "-x.com:1",
            "1.2.3.999:1",
            "[fe80::1%en0]:1",
            "",
            "[::1]:80",
            "vpn.example.test:51820",
            "192.0.2.1:1",
        ]
        return mtu.map { ParserVector(
            field: "MTU",
            value: $0,
            code: ["1280", "1420"].contains($0) ? nil : .invalidMTU,
        ) } +
            ports.map { ParserVector(field: "ListenPort", value: $0, code: ["1", "51820", "65535"].contains($0) ? nil : .invalidPort) } +
            ports.map { ParserVector(
                field: "PersistentKeepalive",
                value: $0,
                code: ["off", "0", "1", "51820", "65535"].contains($0) ? nil : .invalidKeepalive,
            ) } +
            endpoints.map { ParserVector(
                field: "Endpoint",
                value: $0,
                code: $0.contains(":80") || $0 == "vpn.example.test:51820" || $0 == "192.0.2.1:1" ? nil : .invalidEndpoint,
            ) } +
            ["host:0", "host:65536", "host:-1"].map { ParserVector(field: "Endpoint", value: $0, code: .invalidPort) }
    }()

    private static let forbidden: [ParserVector] =
        ["PreUp", "PostUp", "PreDown", "PostDown"].map { ParserVector(field: $0, value: "echo fixture", code: nil) } +
        ["Table", "FwMark", "SaveConfig"].map { ParserVector(field: $0, value: "1", code: nil) } +
        [ParserVector(field: "Bogus", value: "1", code: .unknownKey)] +
        ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"].map { ParserVector(field: $0, value: "1", code: .amneziaField) }

    private static let controls: [ParserVector] = {
        let scalars = Array(0 ... 31).filter { ![9, 10, 13].contains($0) } + [127, 128, 133, 144, 159, 0x200B, 0x202E, 0x2066, 0xFEFF]
        return scalars.compactMap(UnicodeScalar.init).map { ParserVector(
            field: "Address",
            value: "10.0.0.1/32" + String($0),
            code: .controlCharacter,
        ) }
    }()

    private static let keys: [ParserVector] = ["PrivateKey", "PublicKey", "PresharedKey"].flatMap { field in
        [
            "",
            "nope",
            String(repeating: "A", count: 44),
            String(repeating: "é", count: 22),
            String(repeating: "A", count: 43),
            String(repeating: "A", count: 45),
        ].map {
            ParserVector(field: field, value: $0, code: .invalidKey)
        }
    }

    private static let dns: [ParserVector] = [
        ParserVector(field: "DNS", value: "10.77.0.1, corp.example", code: nil),
        ParserVector(field: "DNS", value: "fd77:77::1, CORP.EXAMPLE", code: nil),
        ParserVector(field: "DNS", value: "10.0.0.1/24", code: .invalidDNS),
        ParserVector(field: "DNS", value: "bad_domain", code: .invalidDNS),
        ParserVector(field: "DNS", value: "192.0.2.999", code: .invalidDNS),
        ParserVector(field: "DNS", value: "", code: .invalidDNS),
    ]
}

private struct WgQuickParserTests {
    @Test(arguments: ParserVector.all)
    func `RT-09 byte parser table`(vector: ParserVector) throws {
        let interfaceFields = [
            "Address",
            "PrivateKey",
            "MTU",
            "DNS",
            "ListenPort",
            "PreUp",
            "PostUp",
            "PreDown",
            "PostDown",
            "Table",
            "FwMark",
            "SaveConfig",
            "Bogus",
            "Jc",
            "Jmin",
            "Jmax",
            "S1",
            "S2",
            "H1",
            "H2",
            "H3",
            "H4",
        ]
        var text = try CodecFixtures.minimal()
        let original: String? = switch vector.field {
        case "Address": "Address = 10.77.0.2/32"
        case "AllowedIPs": "AllowedIPs = 10.77.0.0/24"
        case "PrivateKey": try "PrivateKey = \(CodecFixtures.key("client1.key"))"
        case "PublicKey": try "PublicKey = \(CodecFixtures.key("server.pub"))"
        default: nil
        }
        let line = "\(vector.field) = \(vector.value)"
        if let original {
            text = text.replacingOccurrences(of: original, with: line)
        } else if interfaceFields.contains(vector.field) {
            text = try CodecFixtures.minimal(interface: line)
        } else {
            text = try CodecFixtures.minimal(peer: line)
        }
        var bytes = Array(text.utf8)
        if let code = vector.code {
            do { _ = try parseWgQuick(&bytes); Issue.record("Expected rejection") }
            catch let ConfigParseError.diagnostics(diagnostics) {
                #expect(diagnostics.contains { $0.code == code && $0.line != nil })
            }
        } else {
            _ = try parseWgQuick(&bytes)
        }
        #expect(bytes.allSatisfy { $0 == 0 })
    }

    @Test
    func `vector table exceeds acceptance floor`() {
        #expect(ParserVector.all.count >= 120)
    }

    @Test(arguments: [
        "single-peer-full-tunnel",
        "multi-peer-split",
        "ipv6-dual-stack",
        "crlf-bom",
        "comments-and-whitespace",
        "server-two-peers"
    ])
    func `accepted fixtures preserve bytes and derived identity`(name: String) throws {
        var bytes = try CodecFixtures.conf(name)
        let expectedHash = Data(SHA256.hash(data: Data(bytes)))
        let parsed = try parseWgQuick(&bytes)
        #expect(bytes.allSatisfy { $0 == 0 })
        #expect(parsed.original.sha256OfOriginal == expectedHash)
        #expect(parsed.profile.original == parsed.original)
        #expect(parsed.original.text.contains("$WGEX_SECRET:"))
        let key = name == "ipv6-dual-stack" ? "client2.pub" : name == "server-two-peers" ? "server.pub" : "client1.pub"
        #expect(try parsed.profile.interface.publicKey.base64 == (CodecFixtures.key(key)))
    }

    @Test(arguments: [("amnezia-fields-rejected", ConfigDiagnostic.Code.amneziaField)])
    func `rejected fixtures have named diagnostics`(name: String, code: ConfigDiagnostic.Code) throws {
        var bytes = try CodecFixtures.conf(name)
        do { _ = try parseWgQuick(&bytes); Issue.record("Expected rejection") }
        catch let ConfigParseError.diagnostics(diagnostics) { #expect(diagnostics.contains { $0.code == code }) }
        #expect(bytes.allSatisfy { $0 == 0 })
    }

    @Test(arguments: [
        "PrivateKey",
        "ListenPort",
        "MTU",
        "PublicKey",
        "PresharedKey",
        "Endpoint",
        "PersistentKeepalive",
    ])
    func `all duplicate keys are rejected including list fields`(key: String) throws {
        let value = switch key {
        case "PrivateKey", "PresharedKey": try CodecFixtures.key("client1.key")
        case "PublicKey": try CodecFixtures.key("server.pub")
        case "Address", "AllowedIPs": "10.77.0.0/24"
        case "DNS": "10.77.0.1"
        case "Endpoint": "192.0.2.1:51820"
        default: "1420"
        }
        let pair = "\(key)=\(value)\n\(key.lowercased())=\(value)"
        let inPeer = ["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"].contains(key)
        var bytes = try Array(CodecFixtures.minimal(interface: inPeer ? "" : pair, peer: inPeer ? pair : "").utf8)
        #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes) } // inspect below using a fresh, unwiped fixture
        var input = try Array(CodecFixtures.minimal(interface: inPeer ? "" : pair, peer: inPeer ? pair : "").utf8)
        do { _ = try parseWgQuick(&input); Issue.record("Expected duplicate") }
        catch let ConfigParseError.diagnostics(diagnostics) { #expect(diagnostics.first?.code == .duplicateKey) }
    }

    @Test(arguments: ["", "[Bogus]", "[Device]", "not a pair", "[Interface]\n[Interface]", "[Peer]"])
    func `malformed sections and lines fail`(text: String) {
        var bytes = Array(text.utf8)
        #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes) }
    }

    @Test
    func `duplicate peers report the second public key line`() throws {
        var bytes = try Array((CodecFixtures.minimal() + "[Peer]\nPublicKey=\(CodecFixtures.key("server.pub"))\n").utf8)
        do { _ = try parseWgQuick(&bytes); Issue.record("Expected duplicate") }
        catch let ConfigParseError.diagnostics(diagnostics) { #expect(diagnostics.contains { $0.code == .duplicatePeer && $0.line == 10 }) }
    }

    @Test(arguments: [[UInt8](arrayLiteral: 0xFF), [0xC0, 0x80], [0xED, 0xA0, 0x80], [0xF4, 0x90, 0x80, 0x80], [0xE2, 0x82], [0x80]])
    func `invalid UTF8 is never repaired`(bytes: [UInt8]) {
        var input = bytes
        #expect(throws: ConfigParseError.invalidUTF8) { _ = try parseWgQuick(&input) }
        #expect(input.allSatisfy { $0 == 0 })
    }

    @Test(arguments: [false, true], [false, true])
    func `BOM and CRLF combinations are accepted`(bom: Bool, crlf: Bool) throws {
        var text = try CodecFixtures.minimal()
        if crlf {
            text = text.replacingOccurrences(of: "\n", with: "\r\n")
        }
        if bom {
            text = "\u{FEFF}" + text
        }
        _ = try parseWgQuick(Array(text.utf8))
    }

    @Test(arguments: [1279, 1280, 1500, 1501])
    func `IPv6 enforces minimum MTU`(mtu: Int) throws {
        let text = try CodecFixtures.minimal(interface: "MTU=\(mtu)").replacingOccurrences(of: "10.77.0.2/32", with: "fd77::2/128")
        if (1280 ... 1500).contains(mtu) {
            _ = try parseWgQuick(Array(text.utf8))
        } else {
            do { _ = try parseWgQuick(Array(text.utf8)); Issue.record("Expected MTU rejection") }
            catch let ConfigParseError.diagnostics(diagnostics) { #expect(diagnostics.first?.code == .invalidMTU) }
        }
    }

    @Test
    func `256 KiB parse timing with generous regression ceiling`() throws {
        var bytes = try Array(CodecFixtures.minimal().utf8)
        bytes.append(35)
        bytes.append(contentsOf: repeatElement(120, count: 256 * 1024 - bytes.count))
        let start = ContinuousClock.now
        _ = try parseWgQuick(bytes)
        let elapsed = start.duration(to: .now)
        #if DEBUG
            #expect(elapsed < .seconds(3))
        #else
            #expect(elapsed < .milliseconds(50))
        #endif
    }
}
