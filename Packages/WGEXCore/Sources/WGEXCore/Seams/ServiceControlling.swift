// SPDX-License-Identifier: MIT

/// Registration of the Mac daemon (02 §3). The real `ServiceController` lives
/// in `WGEXDaemonClient`; UI tests and debug windows use `FakeServiceController`.
public protocol ServiceControlling: Sendable {
    /// Registration state, starting with the current one.
    var state: AsyncStream<ServiceState> { get }
    /// Registers the daemon.
    func register() async throws(ServiceError)
    /// Unregisters the daemon.
    func unregister() async throws(ServiceError)
    /// Opens the system approval UI.
    func openApproval()
}
