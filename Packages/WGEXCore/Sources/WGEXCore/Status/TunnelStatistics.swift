// SPDX-License-Identifier: MIT

import Foundation

/// Public statistics DTO; never carries key material (02 §3).
public struct TunnelStatistics: Codable, Sendable, Hashable {
    /// Generation the sample belongs to.
    public var generation: UInt64
    /// Sample time.
    public var sampledAt: Date
    /// Interface name, for example `utun7`.
    public var interfaceName: String?
    /// Local listen port.
    public var listenPort: UInt16?
    /// Per-peer counters.
    public var peers: [PeerStatistics]

    /// Creates a sample.
    public init(
        generation: UInt64,
        sampledAt: Date,
        interfaceName: String?,
        listenPort: UInt16?,
        peers: [PeerStatistics],
    ) {
        self.generation = generation
        self.sampledAt = sampledAt
        self.interfaceName = interfaceName
        self.listenPort = listenPort
        self.peers = peers
    }
}
