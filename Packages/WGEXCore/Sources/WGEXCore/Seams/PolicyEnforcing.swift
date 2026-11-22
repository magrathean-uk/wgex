// SPDX-License-Identifier: MIT

/// Daemon port for the packet filter (02 §7.4); `FakePolicyEnforcer` stands in for tests.
public protocol PolicyEnforcing: Sendable {
    /// Moves the anchor to `policy`.
    func apply(_ policy: PacketFilterPolicy) async throws(DaemonPortError)
    /// The policy currently loaded.
    func current() async -> PacketFilterPolicy
}
