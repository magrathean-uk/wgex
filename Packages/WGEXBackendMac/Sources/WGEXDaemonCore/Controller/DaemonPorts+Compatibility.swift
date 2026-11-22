// SPDX-License-Identifier: MIT
import WGEXCore
import WGEXDaemonProtocol

public extension DaemonPorts {
    /// Adapts phase-zero Core ports without runtime capability discovery.
    /// Ports without DNS observation or cache state retain the documented fail-closed defaults.
    init(
        engineFactory: any DaemonEngineCreating, routes: any RouteProgramming, dns: any DNSConfigurating,
        policy: any DaemonPolicyManaging, resolver: any UnderlayResolving, device: any TunnelDeviceConfiguring,
        verifier: any ProtectionVerifying, reality: any DaemonRealityInspecting,
    ) {
        self.init(
            engineFactory: engineFactory, routes: LegacyRoutePort(base: routes), dns: LegacyDNSPort(base: dns), policy: policy,
            resolver: LegacyResolverPort(base: resolver), device: device, verifier: verifier, reality: reality,
        )
    }
}

private struct LegacyDNSPort: DaemonDNSConfiguring {
    let base: any DNSConfigurating

    func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure) {
        do { try await base.apply(configuration, generation: generation) }
        catch { throw DaemonFailure.adaptingPort(error) }
    }

    func remove(generation: Generation) async throws(DaemonFailure) {
        do { try await base.remove(generation: generation) }
        catch { throw DaemonFailure.adaptingPort(error) }
    }

    func current() async -> DNSConfiguration? {
        await base.current()
    }
}

private struct LegacyResolverPort: DaemonUnderlayResolving {
    let base: any UnderlayResolving

    func resolve(host: String, interfaceIndex: UInt32) async throws(DaemonFailure) -> [String] {
        do { return try await base.resolve(host: host, interfaceIndex: interfaceIndex) }
        catch { throw DaemonFailure.adaptingPort(error) }
    }
}

private struct LegacyRoutePort: DaemonRouteProgramming {
    let base: any RouteProgramming
    func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonFailure) {
        do { try await base.install(routes, generation: generation) }
        catch { throw DaemonFailure.adaptingPort(error) }
    }

    func removeRoutes(of generation: Generation) async throws(DaemonFailure) {
        do { try await base.removeRoutes(of: generation) }
        catch { throw DaemonFailure.adaptingPort(error) }
    }

    func ownedRoutes() async -> [RouteSpec] {
        await base.ownedRoutes()
    }
}
