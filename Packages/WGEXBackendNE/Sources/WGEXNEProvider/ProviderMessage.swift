// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

public enum ProviderMessage: Codable, Sendable, Hashable {
    case status, statistics
    case subscribeStats(interval: TimeInterval)
    case unsubscribeStats
    case reload(profileID: UUID)
    case setTransport(TransportSpec)
    case logs(since: Date?)
}

public enum ProviderReply: Codable, Sendable, Hashable {
    case ok
    case status(TunnelStatus)
    case statistics(TunnelStatistics)
    case logs([String])
    case error(TunnelError)
}

/// The same wire definition is compiled into each product without an engine dependency in the client.
public enum ProviderCodec {
    public static let maximumBytes = 256 * 1024
    public static let version = 1
    public enum Failure: Error, Sendable { case oversized, unsupportedVersion }

    private struct Envelope<Body: Codable>: Codable {
        let version: Int
        let body: Body
    }

    public static func encode(_ body: some Codable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(Envelope(version: version, body: body))
        guard data.count <= maximumBytes else { throw Failure.oversized }
        return data
    }

    public static func decode<Body: Codable>(_ type: Body.Type, from data: Data) throws -> Body {
        guard data.count <= maximumBytes else { throw Failure.oversized }
        let envelope = try JSONDecoder().decode(Envelope<Body>.self, from: data)
        guard envelope.version == version else { throw Failure.unsupportedVersion }
        return envelope.body
    }
}
