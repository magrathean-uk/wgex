// SPDX-License-Identifier: MIT
import Foundation

public enum ProtectionTrigger: Sendable, Equatable { case route, configuration, wake, buildChanged, periodic }

public protocol KillSwitchMonitoring: Sendable {
    func shouldVerify(trigger: ProtectionTrigger, enforcing: Bool, now: Duration) async -> Bool
}

public actor KillSwitchMonitor: KillSwitchMonitoring {
    private var lastCheck: Duration?
    public init() {}
    public func shouldVerify(trigger: ProtectionTrigger, enforcing: Bool, now: Duration) -> Bool {
        guard enforcing else { lastCheck = nil; return false }
        if trigger == .periodic, let lastCheck, now - lastCheck < .seconds(5) {
            return false
        }
        lastCheck = now; return true
    }
}
