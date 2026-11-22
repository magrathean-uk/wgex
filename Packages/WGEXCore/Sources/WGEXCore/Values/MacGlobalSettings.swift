// SPDX-License-Identifier: MIT

/// Daemon-global Mac settings, not per profile (02 §3; XPC `setGlobalSettings`).
public struct MacGlobalSettings: Codable, Sendable, Hashable {
    /// Defaults for a new installation.
    public static let defaults = MacGlobalSettings(
        lockdown: false,
        allowLAN: true,
        captiveWindowSeconds: 300,
        notifications: true,
    )

    /// Lockdown (ADR-009).
    public var lockdown: Bool
    /// Allow the underlay's own subnet while protected; default true.
    public var allowLAN: Bool
    /// Captive window length; default 300.
    public var captiveWindowSeconds: Int
    /// User notifications; default true.
    public var notifications: Bool

    /// Creates a settings value.
    public init(lockdown: Bool, allowLAN: Bool, captiveWindowSeconds: Int, notifications: Bool) {
        self.lockdown = lockdown
        self.allowLAN = allowLAN
        self.captiveWindowSeconds = captiveWindowSeconds
        self.notifications = notifications
    }
}
