// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface

public struct NetworkProtectionVerifier: ProtectionVerifying {
    private let routes: any OwnedRouteInspecting
    private let dns: any DaemonDNSConfiguring
    private let identities: any InterfaceIdentityReading
    private let policy: any DaemonPolicyManaging
    public init(
        routes: any OwnedRouteInspecting,
        dns: any DaemonDNSConfiguring,
        identities: any InterfaceIdentityReading,
        policy: any DaemonPolicyManaging,
    ) {
        self.routes = routes; self.dns = dns; self.identities = identities; self.policy = policy
    }

    public func verify(_ expectation: ProtectionExpectation) async throws {
        #if WGEX_LAB_BUILD
            var verdict = PFVerificationStatus.unknown
            defer { DaemonDiagnostics.verifier(verdict) }
        #endif
        // The order of the checks is unchanged; each refusal names its check in Lab builds (M1-17 D12). The tunnel is
        // fenced by name, index, this process's descriptor and the assigned addresses, never by a stamp (M1-18).
        let resources = expectation.resources
        guard let identity = resources.identity else { throw Self.refused(.tunnelIdentityMissing) }
        if case let (breach, current)? = try await identities.breach(of: identity, fence: .tunnel(addresses: resources.addresses)) {
            throw Self.refused(.tunnelIdentityDrift, identity, current, breach)
        }
        let observed = try await Set(routes.observed(resources).map(\.route))
        guard observed == Set(resources.routes) else { throw await routeRefusal(resources, observed: observed) }
        guard await policy.current() == expectation.policy else { throw Self.refused(.policyMismatch) }
        do { try await dns.verify(resources) } catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.ownership(.dnsUnverified)
            #endif
            throw error
        }
        // The controller measures PF on apply or at the liveness boundary, once per transition.
        guard await policy.verification() == TunnelController.expectedVerification(expectation.policy) else {
            throw DaemonFailure.pfVerification
        }
        let stats = try await expectation.engine.statistics()
        guard stats.interfaceName == identity.name else { throw Self.refused(.engineInterfaceMismatch) }
        #if WGEX_LAB_BUILD
            verdict = TunnelController.expectedVerification(expectation.policy)
        #endif
    }

    private static func refused(
        _ event: DaemonDiagnostics.OwnershipEvent, _ expected: TunnelIdentity? = nil, _ current: TunnelIdentity? = nil,
        _ breach: InterfaceFence.Breach? = nil,
    ) -> DaemonFailure {
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(event)
            if let expected, let breach {
                DaemonDiagnostics.interface(expected, current: current, breach: breach)
            }
        #endif
        return .portNotOwned
    }

    /// Names the missing route class; for the canary also which check of the physical interface's fence failed.
    private func routeRefusal(_ resources: GenerationResources, observed: Set<RouteSpec>) async -> DaemonFailure {
        #if WGEX_LAB_BUILD
            if let canary = resources.canaryRoute, !canary.routes.allSatisfy(observed.contains) {
                DaemonDiagnostics.ownership(.canaryRouteMissing)
                if case let (breach, current)? = try? await identities.breach(of: canary.identity, fence: .underlay) {
                    DaemonDiagnostics.ownership(.canaryIdentityDrift)
                    DaemonDiagnostics.interface(canary.identity, current: current, breach: breach)
                }
            }
            if resources.routes.contains(where: { resources.canaryRoute?.routes.contains($0) != true && !observed.contains($0) }) {
                DaemonDiagnostics.ownership(.tunnelRouteMissing)
            }
        #endif
        return .portNotOwned
    }
}

public struct NetworkRealityInspector: DaemonRealityInspecting {
    private let routes: any OwnedRouteInspecting
    private let dns: any DaemonDNSConfiguring
    private let identities: any InterfaceIdentityReading
    public init(routes: any OwnedRouteInspecting, dns: any DaemonDNSConfiguring, identities: any InterfaceIdentityReading) {
        self.routes = routes; self.dns = dns; self.identities = identities
    }

    public func inspect(_ resources: GenerationResources) async throws -> DaemonRealitySnapshot {
        let identity = try await resources.identity.flatMapAsync { try await identities.identity(named: $0.name) }
        let value: SyntheticDNSValue? = if let key = resources.dnsKey {
            try await dns.read(key: key)
        } else {
            nil
        }
        return try await DaemonRealitySnapshot(
            identity: identity, routes: routes.observed(resources),
            dnsKey: value == nil ? nil : resources.dnsKey, dns: value?.configuration,
        )
    }

    public func removeOwned(_ resources: GenerationResources) async throws {
        if resources.dnsKey != nil {
            try await dns.remove(generation: resources.generation)
        }
        if !resources.routes.isEmpty {
            try await routes.removeRoutes(of: resources.generation)
        } else {
            // observed() fences the canary by en0's name, index and link-layer address; when that fence refuses (for
            // example a changed link-layer address), the journalled canary is still torn down under RouteTable's
            // teardown fence (name, index, mark, scope, router) before the caller retires the record (M1-17 F2).
            // Without a journalled canary this is a no-op.
            try await routes.removeCanaryRoute(of: resources.generation)
        }
    }
}

private extension Optional where Wrapped: Sendable {
    func flatMapAsync<Result: Sendable>(_ body: (Wrapped) async throws -> Result?) async rethrows -> Result? {
        guard let value = self else { return nil }; return try await body(value)
    }
}
