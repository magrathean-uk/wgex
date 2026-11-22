// SPDX-License-Identifier: MIT

import Foundation

/// Engine-event-driven health (02 §4.1).
public struct TunnelHealth: Codable, Sendable, Hashable {
    /// Health level per `WGEXPolicy.HealthEvaluator`.
    public enum Level: Codable, Sendable, Hashable {
        /// Handshakes and traffic flow.
        case healthy
        /// No traffic for 60 s and no failure; a display state, never an error.
        case idle
        /// One 15-s window of tx without rx.
        case degraded(reason: String)
        /// Two consecutive windows of tx without rx.
        case unresponsive
        /// The path is unsatisfied.
        case offline
    }

    /// Health of an idle tunnel with no samples.
    public static let idle = TunnelHealth(level: .idle, lastHandshake: nil, rxRate: 0, txRate: 0)

    /// Current level.
    public var level: Level
    /// Wall-clock time of the last completed handshake.
    public var lastHandshake: Date?
    /// Receive rate in bytes per second.
    public var rxRate: Double
    /// Transmit rate in bytes per second.
    public var txRate: Double

    /// Creates a health value.
    public init(level: Level, lastHandshake: Date?, rxRate: Double, txRate: Double) {
        self.level = level
        self.lastHandshake = lastHandshake
        self.rxRate = rxRate
        self.txRate = txRate
    }
}
