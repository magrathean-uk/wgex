// SPDX-License-Identifier: MIT

/// What a ``TunnelBackend`` can do on its platform.
public struct BackendCapabilities: OptionSet, Codable, Sendable, Hashable {
    /// Traffic outside the tunnel is blocked while connecting or failed.
    public static let killSwitch = BackendCapabilities(rawValue: 1 << 0)
    /// Global lockdown that persists without the app (Mac).
    public static let lockdown = BackendCapabilities(rawValue: 1 << 1)
    /// Timed captive-portal window (Mac).
    public static let captiveWindow = BackendCapabilities(rawValue: 1 << 2)
    /// On-demand rules (iOS, tvOS).
    public static let onDemand = BackendCapabilities(rawValue: 1 << 3)
    /// Connect before any user logs in (Mac).
    public static let startBeforeLogin = BackendCapabilities(rawValue: 1 << 4)
    /// Transport switching without a restart.
    public static let transportSwitching = BackendCapabilities(rawValue: 1 << 5)
    /// Allow-LAN exception while protected.
    public static let allowLAN = BackendCapabilities(rawValue: 1 << 6)

    /// Bit set.
    public let rawValue: UInt32

    /// Creates a set from raw bits.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
}
