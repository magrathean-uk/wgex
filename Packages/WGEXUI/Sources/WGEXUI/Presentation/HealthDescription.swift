// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Health lines and chips (02 §4.1; copy deck). "Connected, idle" is a
/// display state, never an error.
public nonisolated enum HealthDescription {
    /// One line describing health, with the handshake age as evidence.
    public static func line(for health: TunnelHealth, now: Date) -> String {
        switch health.level {
        case .healthy:
            if health.rxRate > 0 || health.txRate > 0 {
                return MacStrings.connectedTransferring
            }
            return health.lastHandshake.map { MacStrings.connectedLastHandshake(String(UIFormat.ago($0, now: now))) } ?? MacStrings
                .connected
        case .idle:
            return MacStrings.connectedIdle
        case .degraded:
            return MacStrings.connectedWaitingForThePeer(String(handshakeClause(health.lastHandshake, now: now)))
        case .unresponsive:
            return MacStrings.connectedPeerNotResponding(String(handshakeClause(health.lastHandshake, now: now)))
        case .offline:
            return MacStrings.connectedNoNetworkAvailable
        }
    }

    /// Chip for the orb when health needs attention; nil when healthy or idle.
    public static func chip(for health: TunnelHealth) -> OrbChip? {
        switch health.level {
        case .healthy, .idle:
            nil
        case .degraded:
            OrbChip(slot: .health, glyph: "exclamationmark.triangle", title: MacStrings.slowReplies, colour: .unknown)
        case .unresponsive:
            OrbChip(slot: .health, glyph: "exclamationmark.triangle.fill", title: MacStrings.noResponse, colour: .unknown)
        case .offline:
            OrbChip(slot: .health, glyph: "wifi.slash", title: MacStrings.noNetwork, colour: .unknown)
        }
    }

    /// "last handshake 3 min ago" or "no handshake yet".
    public static func handshakeClause(_ lastHandshake: Date?, now: Date) -> String {
        lastHandshake.map { MacStrings.lastHandshake(String(UIFormat.ago($0, now: now))) } ?? MacStrings.noHandshakeYet
    }
}
