// SPDX-License-Identifier: MIT

import Synchronization
import WGEXCore

/// ``PolicyEnforcing`` stand-in that keeps the history of applied policies;
/// fault point `apply`.
public final class FakePolicyEnforcer: PolicyEnforcing {
    /// Faults consumed by `apply`.
    public let faults: FaultInjector
    private let applied = Mutex<[PacketFilterPolicy]>([])

    /// Creates an enforcer in `.disconnected`.
    public init(faults: FaultInjector = FaultInjector()) {
        self.faults = faults
    }

    /// Every policy applied, oldest first.
    public var history: [PacketFilterPolicy] {
        applied.withLock { $0 }
    }

    /// Records the policy.
    public func apply(_ policy: PacketFilterPolicy) async throws(DaemonPortError) {
        if let error = faults.fault(at: "apply", as: DaemonPortError.self) {
            throw error
        }
        applied.withLock { $0.append(policy) }
    }

    /// The last policy applied, or `.disconnected`.
    public func current() async -> PacketFilterPolicy {
        applied.withLock { $0.last ?? .disconnected }
    }
}
