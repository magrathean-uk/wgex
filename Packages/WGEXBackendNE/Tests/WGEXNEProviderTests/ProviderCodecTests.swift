// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXNEProvider

private struct ProviderCodecTests {
    @Test
    func `all messages and replies round trip with version one`() throws {
        let messages: [ProviderMessage] = [
            .status, .statistics, .subscribeStats(interval: 2), .unsubscribeStats,
            .reload(profileID: UUID()), .setTransport(.udp), .logs(since: Date(timeIntervalSince1970: 0)),
        ]
        for message in messages {
            let bytes = try ProviderCodec.encode(message)
            #expect(try ProviderCodec.decode(ProviderMessage.self, from: bytes) == message)
        }
        let replies: [ProviderReply] = [.ok, .status(.idle), .logs(["public event"]), .error(.timedOut), .statistics(TunnelStatistics(
            generation: 0, sampledAt: Date(timeIntervalSince1970: 0), interfaceName: nil, listenPort: nil, peers: [],
        ))]
        for reply in replies {
            #expect(try ProviderCodec.decode(ProviderReply.self, from: ProviderCodec.encode(reply)) == reply)
        }
    }

    @Test
    func `exactly 256 KiB is accepted`() throws {
        let overhead = try ProviderCodec.encode(ProviderReply.logs([""])).count
        let value = ProviderReply.logs([String(repeating: "x", count: ProviderCodec.maximumBytes - overhead)])
        let bytes = try ProviderCodec.encode(value)
        #expect(bytes.count == ProviderCodec.maximumBytes)
        #expect(try ProviderCodec.decode(ProviderReply.self, from: bytes) == value)
    }

    @Test
    func `size limit rejects inbound and outbound and unknown version rejects`() throws {
        #expect(throws: ProviderCodec.Failure.oversized) {
            try ProviderCodec.encode(ProviderReply.logs([String(repeating: "x", count: ProviderCodec.maximumBytes)]))
        }
        #expect(throws: ProviderCodec.Failure.oversized) {
            try ProviderCodec.decode(ProviderMessage.self, from: Data(repeating: 0, count: ProviderCodec.maximumBytes + 1))
        }
        let valid = try ProviderCodec.encode(ProviderMessage.status)
        let changed = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "\"version\":1", with: "\"version\":2").utf8)
        #expect(throws: ProviderCodec.Failure.unsupportedVersion) { try ProviderCodec.decode(ProviderMessage.self, from: changed) }
    }
}
