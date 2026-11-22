// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy
import WGEXTesting

/// Always-verified install state: the export path under test does not exercise installation checks.
package struct ExportVerifiedInstall: SecureInstallChecking {
    package func status() -> SecureInstallReport {
        SecureInstallReport(
            state: .verified, bundlePath: "/Applications/WGEX.app", isUnderApplications: true,
            bundleIdentity: .matched, daemonIdentity: .matched,
        )
    }

    package func perform() -> SecureInstallReport {
        status()
    }
}

/// Minimal in-memory host ports for the real controller: no route, DNS, pf or utun is touched.
package actor ExportPorts: DaemonEngineCreating, DaemonRouteProgramming, DaemonDNSConfiguring, DaemonPolicyManaging,
    DaemonUnderlayResolving, TunnelDeviceConfiguring, ProtectionVerifying, DaemonRealityInspecting
{
    package static let nextDescriptor = Atomic<Int32>(900)
    private var routeItems: [Generation: [RouteSpec]] = [:]
    private var dnsItems: [Generation: DNSConfiguration] = [:]
    private var identities: [Generation: TunnelIdentity] = [:]
    private var policy: PacketFilterPolicy = .disconnected
    private var token: String?
    package private(set) var engine: FakeEngine?
    package let pfToken: String

    package init(pfToken: String) {
        self.pfToken = pfToken
    }

    package func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
        let created = try FakeEngine(configuration: configuration)
        let fd = Self.nextDescriptor.add(1, ordering: .relaxed).newValue
        let identity = TunnelIdentity(
            name: "utun-export", interfaceIndex: 100, descriptor: TunnelDescriptor(fd: fd, generation: generation),
        )
        engine = created; identities[generation] = identity
        return CreatedDaemonEngine(engine: created, identity: identity)
    }

    package func canaryRoute(underlay _: UnderlaySnapshot) -> OwnedCanaryRoute? {
        nil
    }

    package func install(_ routes: [RouteSpec], generation: Generation) {
        routeItems[generation] = routes
    }

    package func removeRoutes(of generation: Generation) {
        routeItems.removeValue(forKey: generation)
    }

    package func ownedRoutes() -> [RouteSpec] {
        routeItems.values.flatMap(\.self)
    }

    package func apply(_ configuration: DNSConfiguration, generation: Generation) {
        dnsItems[generation] = configuration
    }

    package func remove(generation: Generation) {
        dnsItems.removeValue(forKey: generation)
    }

    package func current() -> DNSConfiguration? {
        dnsItems.values.first
    }

    package func apply(_ policy: PacketFilterPolicy) {
        self.policy = policy
    }

    package func current() -> PacketFilterPolicy {
        policy
    }

    package func verification() -> PFVerificationStatus {
        switch policy {
        case .error, .lockdown, .disconnecting, .connecting: .blocked
        case .connected: .protected
        case .captiveWindow: .captiveWindow
        case .disconnected: .unprotected
        }
    }

    package func setModifiers(_: PolicyModifiers) {}
    package func configureProfile(_: TunnelProfile) {}
    package func verifyEvaluation() {}
    package func acquireToken(existing: String?) -> String {
        token = existing ?? token ?? pfToken; return token ?? pfToken
    }

    package func releaseToken(_: String) {
        token = nil
    }

    package func resolve(host _: String, interfaceIndex _: UInt32) -> [String] {
        ["192.0.2.1"]
    }

    package func configure(_: TunnelIdentity, addresses _: [IPAddressRange], mtu _: UInt16, generation _: Generation) {}
    package func removeAddresses(_: TunnelIdentity, generation _: Generation) {}
    package func identity(afterConfiguring identity: TunnelIdentity, engine _: any EngineControlling?) -> TunnelIdentity {
        identity
    }

    package func verify(_: ProtectionExpectation) {}
    package func inspect(_ resources: GenerationResources) -> DaemonRealitySnapshot {
        let identity = identities[resources.generation]
        let routes = (routeItems[resources.generation] ?? []).compactMap { route -> ObservedDaemonRoute? in
            guard let identity else { return nil }
            return ObservedDaemonRoute(route: route, identity: identity, generation: resources.generation, hasProtocol2Flag: true)
        }
        return DaemonRealitySnapshot(identity: identity, routes: routes, dnsKey: resources.dnsKey, dns: dnsItems[resources.generation])
    }

    package func removeOwned(_ resources: GenerationResources) {
        identities.removeValue(forKey: resources.generation)
        routeItems.removeValue(forKey: resources.generation)
        dnsItems.removeValue(forKey: resources.generation)
    }
}
