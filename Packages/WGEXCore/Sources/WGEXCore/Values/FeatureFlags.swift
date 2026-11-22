// SPDX-License-Identifier: MIT

/// Runtime feature toggles present in release builds (02 §3).
public struct FeatureFlags: Codable, Sendable, Hashable {
    /// Defaults for a new installation.
    public static let defaults = FeatureFlags(relayTransports: false)

    /// "Experimental: relay transports"; default off.
    public var relayTransports: Bool

    /// Creates a flag set.
    public init(relayTransports: Bool) {
        self.relayTransports = relayTransports
    }
}
