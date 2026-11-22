// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonCore

/// Records verification triggers without inspecting the host firewall.
public actor FakeKillSwitchMonitor: KillSwitchMonitoring {
    /// Verification triggers observed by this fixture.
    public private(set) var triggers: [ProtectionTrigger] = []
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Records this trigger and permits verification when protection is enforcing.
    public func shouldVerify(trigger: ProtectionTrigger, enforcing: Bool, now: Duration) -> Bool {
        triggers.append(trigger); return enforcing
    }
}
