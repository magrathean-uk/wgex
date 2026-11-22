// SPDX-License-Identifier: MIT

/// Daemon port for the routing table (02 §7). Implementations tag and own their
/// routes per generation; `FakeRouteTable` stands in for tests.
public protocol RouteProgramming: Sendable {
    /// Installs `routes` for `generation`.
    func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonPortError)
    /// Removes every route `generation` installed.
    func removeRoutes(of generation: Generation) async throws(DaemonPortError)
    /// Routes currently owned by WGEX.
    func ownedRoutes() async -> [RouteSpec]
}
