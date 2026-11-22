// SPDX-License-Identifier: MIT

/// Daemon port that resolves endpoint names over the physical interface
/// (02 §7.5); `FakeUnderlayResolver` stands in for tests.
public protocol UnderlayResolving: Sendable {
    /// Addresses for `host`, ordered for connection attempts.
    func resolve(host: String, interfaceIndex: UInt32) async throws(DaemonPortError) -> [String]
}
