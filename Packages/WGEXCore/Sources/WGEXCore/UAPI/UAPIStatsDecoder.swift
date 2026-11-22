// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Sources/TunnelCore/RuntimeStats.swift at a27bce1b6f25, MIT
import Foundation

public enum UAPIStatsError: Error, Sendable, Hashable {
    case secretKey
    case invalidDocument
    case limitExceeded
}

/// Decodes the bridge's public JSON, never a secret-bearing UAPI dump. Error values
/// deliberately omit Foundation's decoding context, which may contain input values.
public enum UAPIStatsDecoder {
    public static func decode(_ bytes: borrowing [UInt8], generation: UInt64 = 0) throws(UAPIStatsError) -> TunnelStatistics {
        do {
            try guardKeys(bytes)
            let decoded = try JSONDecoder().decode(Stats.self, from: bytes.withUnsafeBytes { Data($0) })
            guard decoded.peers.count <= 1024 else { throw UAPIStatsError.limitExceeded }
            let peers = try decoded.peers.map { try $0.publicStatistics() }
            guard Set(peers.map(\.publicKey)).count == peers.count else { throw UAPIStatsError.invalidDocument }
            return TunnelStatistics(
                generation: decoded.generation ?? generation, sampledAt: decoded.sampledAt.date,
                interfaceName: decoded.interfaceName, listenPort: decoded.listenPort, peers: peers,
            )
        } catch let error as UAPIStatsError { throw error }
        catch { throw .invalidDocument }
    }

    /// Scans every JSON member name before decoding. Unlike walking a dictionary, this
    /// catches secrets hidden in overwritten duplicate members and unknown nested objects.
    private static func guardKeys(_ bytes: borrowing [UInt8]) throws(UAPIStatsError) {
        guard bytes.count <= 256 * 1024 else { throw .limitExceeded }
        var index = 0; var depth = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 123 || byte == 91 {
                depth += 1
                guard depth <= 64 else { throw .limitExceeded }
            } else if byte == 125 || byte == 93 {
                depth -= 1
            }
            if byte != 34 {
                index += 1; continue
            }
            let start = index; index += 1
            index = try stringEnd(bytes, from: index)
            try checkKey(bytes, range: start ..< index)
        }
    }

    private static func stringEnd(_ bytes: borrowing [UInt8], from start: Int) throws(UAPIStatsError) -> Int {
        var index = start
        while index < bytes.count, bytes[index] != 34 {
            if bytes[index] == 92 {
                index += 1
            }
            index += 1
        }
        guard index < bytes.count else { throw .invalidDocument }
        return index + 1
    }

    private static func checkKey(_ bytes: borrowing [UInt8], range: Range<Int>) throws(UAPIStatsError) {
        var next = range.upperBound
        while next < bytes.count, [9, 10, 13, 32].contains(bytes[next]) {
            next += 1
        }
        guard next < bytes.count, bytes[next] == 58 else { return }
        do {
            let key = try JSONDecoder().decode(String.self, from: Data(bytes[range]))
            if key.lowercased() == "private_key" || key.lowercased() == "preshared_key" {
                throw UAPIStatsError.secretKey
            }
        } catch let error as UAPIStatsError { throw error }
        catch { throw .invalidDocument }
    }
}

private struct Timestamp: Decodable {
    let date: Date

    init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let seconds = try? value.decode(Double.self) {
            guard seconds.isFinite, seconds >= 0 else { throw UAPIStatsError.invalidDocument }
            date = Date(timeIntervalSince1970: seconds)
        } else {
            let text = try value.decode(String.self)
            if let parsed = try? Date(text, strategy: .iso8601.time(includingFractionalSeconds: true)) {
                date = parsed
            } else if let parsed = try? Date(text, strategy: .iso8601) {
                date = parsed
            } else {
                throw UAPIStatsError.invalidDocument
            }
        }
    }
}

private enum StatsCodingKeys: String, CodingKey {
    case generation, peers
    case sampledAt = "sampled_at", interfaceName = "interface_name", listenPort = "listen_port"
}

private enum PeerCodingKeys: String, CodingKey {
    case publicKey = "public_key", endpoint
    case lastHandshakeTime = "last_handshake_time", lastHandshake = "last_handshake"
    case rxBytes = "rx_bytes", txBytes = "tx_bytes"
    case persistentKeepaliveInterval = "persistent_keepalive_interval", persistentKeepalive = "persistent_keepalive"
}

private struct Stats: Decodable {
    let generation: UInt64?
    let sampledAt: Timestamp
    let interfaceName: String?
    let listenPort: UInt16?
    let peers: [Peer]

    private typealias CodingKeys = StatsCodingKeys
}

private struct Peer: Decodable {
    let publicKey: String
    let endpoint: String?
    let lastHandshakeTime: Timestamp?
    let lastHandshake: Timestamp?
    let rxBytes: UInt64
    let txBytes: UInt64
    let persistentKeepaliveInterval: UInt16?
    let persistentKeepalive: UInt16?

    private typealias CodingKeys = PeerCodingKeys

    func publicStatistics() throws -> PeerStatistics {
        let key = try Array(publicKey.utf8).withUnsafeBytes { try PublicKey(parsing: $0, encoding: .base64) }
        let handshake = lastHandshakeTime?.date ?? lastHandshake?.date
        let keepalive = persistentKeepaliveInterval ?? persistentKeepalive
        return try PeerStatistics(
            publicKey: key, endpoint: endpoint.map { try statsEndpoint($0) },
            lastHandshake: handshake?.timeIntervalSince1970 == 0 ? nil : handshake,
            rxBytes: rxBytes, txBytes: txBytes, persistentKeepalive: keepalive == 0 ? nil : keepalive,
        )
    }
}

/// Zones belong to the engine's socket scope, not to a reusable configuration endpoint.
private func statsEndpoint(_ value: String) throws -> Endpoint {
    guard value.hasPrefix("["), let close = value.firstIndex(of: "]"),
          let zone = value[..<close].firstIndex(of: "%") else { return try Endpoint(value) }
    return try Endpoint(String(value[..<zone]) + String(value[close...]))
}
