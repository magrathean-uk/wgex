// SPDX-License-Identifier: MIT

import Foundation

/// Per-peer counters from the engine (02 §3).
public struct PeerStatistics: Codable, Sendable, Hashable {
    /// Peer public key.
    public var publicKey: PublicKey
    /// Engine-observed (roaming) endpoint.
    public var endpoint: Endpoint?
    /// Wall-clock time of the last handshake.
    public var lastHandshake: Date?
    /// Bytes received.
    public var rxBytes: UInt64
    /// Bytes sent.
    public var txBytes: UInt64
    /// Keepalive interval in seconds.
    public var persistentKeepalive: UInt16?

    /// Creates a counter set.
    public init(
        publicKey: PublicKey,
        endpoint: Endpoint?,
        lastHandshake: Date?,
        rxBytes: UInt64,
        txBytes: UInt64,
        persistentKeepalive: UInt16?,
    ) {
        self.publicKey = publicKey
        self.endpoint = endpoint
        self.lastHandshake = lastHandshake
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.persistentKeepalive = persistentKeepalive
    }
}
