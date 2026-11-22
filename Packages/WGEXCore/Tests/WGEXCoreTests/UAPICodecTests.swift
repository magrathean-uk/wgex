// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Tests/TunnelCoreTests/ReviewAndStatsTests.swift at a27bce1b6f25, MIT
import Foundation
import Testing
import WGEXCore

private struct UAPIEncoderTests {
    @Test(arguments: ["single-peer-full-tunnel", "multi-peer-split", "ipv6-dual-stack"])
    func `full documents match independent golden bytes`(name: String) throws {
        let parsed = try parseWgQuick(CodecFixtures.conf(name))
        var endpoints: [PublicKey: Endpoint] = [:]
        if name == "multi-peer-split" {
            endpoints[parsed.profile.peers[0].publicKey] = try Endpoint("192.0.2.1:51820")
        }
        let document = try UAPIEncoder.fullConfiguration(parsed.profile, secrets: parsed.secrets, endpoints: endpoints)
        let expected = try CodecFixtures.golden(name)
        let equal = document.bytes.withUnsafeBytes { $0.elementsEqual(expected) }
        #expect(equal)
        #expect(document.byteCount == expected.count)
    }

    @Test
    func `endpoint update matches golden without full replacement`() throws {
        let parsed = try parseWgQuick(CodecFixtures.conf("single-peer-full-tunnel"))
        let update = try UAPIEncoder.endpointUpdates([parsed.profile.peers[0].publicKey: Endpoint("[2001:db8::2]:51821")])
        let expected = try CodecFixtures.golden("endpoint-update")
        let equal = update.bytes.withUnsafeBytes { $0.elementsEqual(expected) }
        #expect(equal)
    }

    @Test
    func `RT-04 zero-peer full replacement always clears installed peers`() throws {
        let parsed = try parseWgQuick(CodecFixtures.conf("single-peer-full-tunnel"))
        var profile = parsed.profile; profile.peers = []
        let document = try UAPIEncoder.fullConfiguration(profile, secrets: parsed.secrets)
        let text = document.bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } // throwaway fixtures only
        #expect(text.contains("replace_peers=true\n"))
        #expect(!text.contains("public_key="))
        #expect(!text.contains("fwmark"))
    }

    @Test
    func `hostname endpoints require explicit underlay resolution`() throws {
        let parsed = try parseWgQuick(CodecFixtures.conf("multi-peer-split"))
        #expect(throws: UAPIEncodingError.unresolvedEndpoint) { _ = try UAPIEncoder.fullConfiguration(
            parsed.profile,
            secrets: parsed.secrets,
        ) }
        #expect(throws: UAPIEncodingError.unresolvedEndpoint) {
            _ = try UAPIEncoder.endpointUpdates([parsed.profile.peers[0].publicKey: Endpoint("vpn.example.test:51820")])
        }
        #expect(throws: ConfigurationError.invalidPort) {
            _ = try UAPIEncoder.endpointUpdates([parsed.profile.peers[0].publicKey: Endpoint(host: "192.0.2.1", port: 0)])
        }
    }

    @Test
    func `endpoint updates have deterministic peer order`() throws {
        let parsed = try parseWgQuick(CodecFixtures.conf("multi-peer-split"))
        let first = parsed.profile.peers[0].publicKey; let second = parsed.profile.peers[1].publicKey
        let a = try UAPIEncoder.endpointUpdates([first: Endpoint("192.0.2.1:1"), second: Endpoint("[2001:db8::2]:2")])
        let b = try UAPIEncoder.endpointUpdates([second: Endpoint("[2001:db8::2]:2"), first: Endpoint("192.0.2.1:1")])
        let same = a.bytes.constantTimeEquals(b.bytes)
        #expect(same)
    }
}

private struct UAPIStatsDecoderTests {
    @Test(
        arguments: ["private_key", "preshared_key", "private_\\u006bey", "PRESHARED_KEY"],
        ["root", "peer", "unknown", "duplicate", "array"],
    )
    func `RT-07 rejects secret member names at every depth including escaped and overwritten keys`(key: String, location: String) {
        let member = "\"\(key)\":\"fixture\""
        let body = switch location {
        case "root": "{\(member)}"
        case "peer": "{\"peers\":[{\(member)}]}"
        case "unknown": "{\"ignored\":{\"nested\":{\(member)}}}"
        case "duplicate": "{\"ignored\":{\(member)},\"ignored\":{}}"
        default: "[{\"ignored\":[{\(member)}]}]"
        }
        #expect(throws: UAPIStatsError.secretKey) { _ = try UAPIStatsDecoder.decode(Array(body.utf8)) }
    }

    @Test
    func `engine header shape maps RFC3339 nanoseconds and caller generation`() throws {
        let key = try CodecFixtures.key("server.pub")
        let json = """
        {"interface_name":"utun7","listen_port":51820,"sampled_at":"2025-10-25T05:26:41.125Z","peers":[
        {"public_key":"\(key)","endpoint":"192.0.2.1:51820","last_handshake_time":"2025-10-25T05:26:40.000000005Z","rx_bytes":2000,"tx_bytes":1000,"persistent_keepalive_interval":25}]}
        """
        let stats = try UAPIStatsDecoder.decode(Array(json.utf8), generation: 42)
        #expect(stats.generation == 42)
        #expect(stats.interfaceName == "utun7")
        #expect(stats.listenPort == 51820)
        #expect(stats.sampledAt.timeIntervalSince1970 == 1_761_370_001.125)
        #expect(stats.peers[0].lastHandshake?.timeIntervalSince1970 == 1_761_370_000)
        #expect(stats.peers[0].persistentKeepalive == 25)
        #expect(stats.peers[0].publicKey.base64 == key)
        #expect(stats.peers[0].rxBytes == 2000 && stats.peers[0].txBytes == 1000)
        #expect(stats.peers[0].endpoint?.stringRepresentation == "192.0.2.1:51820")
    }

    @Test
    func `plan snake case DTO supports unix seconds zero handshake and UInt64 counters`() throws {
        let key = try CodecFixtures.key("server.pub")
        let json = """
        {"generation":7,"sampled_at":1700000000.5,"peers":[
        {"public_key":"\(key)","last_handshake":0,"rx_bytes":18446744073709551615,"tx_bytes":0,"persistent_keepalive":0}]}
        """
        let stats = try UAPIStatsDecoder.decode(Array(json.utf8), generation: 99)
        #expect(stats.generation == 7)
        #expect(stats.sampledAt.timeIntervalSince1970 == 1_700_000_000.5)
        #expect(stats.peers[0].rxBytes == UInt64.max)
        #expect(stats.peers[0].lastHandshake == nil)
        #expect(stats.peers[0].persistentKeepalive == nil)
    }

    @Test
    func `no handshake no keepalive and secret words as values are permitted`() throws {
        let key = try CodecFixtures.key("server.pub")
        let json = """
        {"sampled_at":"2025-10-25T05:26:41Z","note":"private_key preshared_key \\\"escaped\\\"","peers":[
        {"public_key":"\(key)","rx_bytes":5,"tx_bytes":0}]}
        """
        let stats = try UAPIStatsDecoder.decode(Array(json.utf8))
        #expect(stats.peers[0].lastHandshake == nil)
        #expect(stats.peers[0].persistentKeepalive == nil)
    }

    @Test(arguments: [
        "",
        "{}",
        "[]",
        "{",
        "{\"sampled_at\":-1,\"peers\":[]}",
        "{\"sampled_at\":\"bad\",\"peers\":[]}",
        "{\"sampled_at\":1,\"listen_port\":65536,\"peers\":[]}",
    ])
    func `malformed public JSON fails without reflecting input`(json: String) {
        #expect(throws: UAPIStatsError.invalidDocument) { _ = try UAPIStatsDecoder.decode(Array(json.utf8)) }
    }

    @Test(arguments: [
        "\"public_key\":\"bad\",\"rx_bytes\":0,\"tx_bytes\":0",
        "\"rx_bytes\":-1,\"tx_bytes\":0",
        "\"rx_bytes\":0,\"tx_bytes\":18446744073709551616",
        "\"rx_bytes\":0,\"tx_bytes\":0,\"endpoint\":\"bad\"",
        "\"rx_bytes\":0,\"tx_bytes\":0,\"persistent_keepalive_interval\":65536"
    ])
    func `invalid peer fields fail`(fields: String) throws {
        let key = try CodecFixtures.key("server.pub")
        let identity = fields.hasPrefix("\"public_key\"") ? "" : "\"public_key\":\"\(key)\","
        let json = "{\"sampled_at\":1,\"peers\":[{\(identity)\(fields)}]}"
        #expect(throws: UAPIStatsError.invalidDocument) { _ = try UAPIStatsDecoder.decode(Array(json.utf8)) }
    }

    @Test
    func `decoder bounds size depth peer count and duplicate peers`() throws {
        #expect(throws: UAPIStatsError.limitExceeded) { _ = try UAPIStatsDecoder.decode(Array(repeating: 32, count: 262_145)) }
        let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
        #expect(throws: UAPIStatsError.limitExceeded) { _ = try UAPIStatsDecoder.decode(Array(deep.utf8)) }
        let key = try CodecFixtures.key("server.pub")
        let peer = "{\"public_key\":\"\(key)\",\"rx_bytes\":0,\"tx_bytes\":0}"
        let many = "{\"sampled_at\":1,\"peers\":[" + Array(repeating: peer, count: 1025).joined(separator: ",") + "]}"
        #expect(throws: UAPIStatsError.limitExceeded) { _ = try UAPIStatsDecoder.decode(Array(many.utf8)) }
        let duplicate = "{\"sampled_at\":1,\"peers\":[\(peer),\(peer)]}"
        #expect(throws: UAPIStatsError.invalidDocument) { _ = try UAPIStatsDecoder.decode(Array(duplicate.utf8)) }
    }
}
