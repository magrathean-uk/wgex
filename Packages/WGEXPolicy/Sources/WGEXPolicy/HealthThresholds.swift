// SPDX-License-Identifier: MIT

import WGEXCore

/// Health evaluation constants from 02 §4.1.
public struct HealthThresholds: Sendable, Hashable {
    /// Thresholds used by every platform.
    public static let standard = HealthThresholds(
        txWithoutRxWindow: .seconds(15),
        idleAfter: .seconds(60),
        unresponsiveWindows: 2,
    )

    /// One window of tx without rx (`KeepaliveTimeout + RekeyTimeout`).
    public var txWithoutRxWindow: Duration
    /// No tx for this long and no failure means idle.
    public var idleAfter: Duration
    /// Consecutive windows before a tunnel is unresponsive.
    public var unresponsiveWindows: Int

    /// Two RekeyTimeout intervals for a requested handshake.
    public var probeGrace: Duration = .seconds(10)
    /// One good window restores health after reception resumes.
    public var recoveryWindow: Duration = .seconds(15)

    /// Creates a threshold set.
    public init(txWithoutRxWindow: Duration, idleAfter: Duration, unresponsiveWindows: Int) {
        self.txWithoutRxWindow = txWithoutRxWindow
        self.idleAfter = idleAfter
        self.unresponsiveWindows = unresponsiveWindows
    }
}
