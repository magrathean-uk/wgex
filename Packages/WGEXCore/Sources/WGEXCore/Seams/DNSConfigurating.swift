// SPDX-License-Identifier: MIT

/// Daemon port for system DNS (02 §7.3); `FakeDNSConfigurator` stands in for tests.
public protocol DNSConfigurating: Sendable {
    /// Publishes `configuration` for `generation`.
    func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonPortError)
    /// Withdraws whatever `generation` published.
    func remove(generation: Generation) async throws(DaemonPortError)
    /// The configuration currently published by WGEX, if any.
    func current() async -> DNSConfiguration?
}
