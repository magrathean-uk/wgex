// SPDX-License-Identifier: MIT
import WGEXCore

/// Unified logging categories under the running build's subsystem.
public enum LogCategory: String, Sendable, CaseIterable {
    case app, daemon, provider, engine, routes, dns, pf, xpc, store, pairing, transport, policy
    /// Retained for source compatibility with the foundation placeholder.
    case service, profiles

    public static var subsystem: String {
        BuildIdentifiers.current.logSubsystem
    }
}
