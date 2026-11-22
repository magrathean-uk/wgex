// SPDX-License-Identifier: MIT

import Foundation

/// The seam between the UI and a platform backend (02 §3): `DaemonClient` on
/// the Mac, `NEManagerClient` on iOS and tvOS, `FakeTunnelBackend` in tests.
public protocol TunnelBackend: Sendable {
    /// What this backend supports.
    var capabilities: BackendCapabilities { get }
    /// Installs or updates a profile.
    func install(_ profile: TunnelProfile) async throws(TunnelError)
    /// Removes a profile, optionally deleting its secrets.
    func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError)
    /// Starts a profile, optionally on a specific transport.
    func start(_ id: UUID, transport: TransportID?) async throws(TunnelError)
    /// Stops a profile.
    func stop(_ id: UUID) async throws(TunnelError)
    /// Status snapshots, starting with the current one.
    func statusUpdates() -> AsyncStream<TunnelStatus>
    /// A statistics sample.
    func statistics() async throws(TunnelError) -> TunnelStatistics
}
