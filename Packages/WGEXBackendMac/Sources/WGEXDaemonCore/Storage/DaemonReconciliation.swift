// SPDX-License-Identifier: MIT
import WGEXCore

public struct ObservedDaemonRoute: Sendable, Hashable {
    public let route: RouteSpec
    public let identity: TunnelIdentity
    public let generation: Generation
    public let hasProtocol2Flag: Bool
    public init(route: RouteSpec, identity: TunnelIdentity, generation: Generation, hasProtocol2Flag: Bool) {
        self.route = route; self.identity = identity; self.generation = generation; self.hasProtocol2Flag = hasProtocol2Flag
    }
}

public struct DaemonRealitySnapshot: Sendable {
    public let identity: TunnelIdentity?
    public let routes: [ObservedDaemonRoute]
    public let dnsKey: String?
    public let dns: DNSConfiguration?
    public init(identity: TunnelIdentity?, routes: [ObservedDaemonRoute], dnsKey: String?, dns: DNSConfiguration?) {
        self.identity = identity; self.routes = routes; self.dnsKey = dnsKey; self.dns = dns
    }
}

/// Pure ownership decision. A name alone, a tag alone, or an index alone never authorises removal.
public enum DaemonReconciliation {
    public static func ownedResources(_ expected: GenerationResources, observed: DaemonRealitySnapshot) -> GenerationResources {
        var owned = GenerationResources(generation: expected.generation)
        // The utun is ours only while this process holds its descriptor; a record without one (before M1-18) never is.
        if let identity = expected.identity, identity.descriptor != nil, observed.identity == identity {
            owned.identity = identity; owned.addresses = expected.addresses
            owned.routes = observed.routes.filter {
                $0.hasProtocol2Flag && $0.identity == identity && $0.generation == expected.generation && expected.routes.contains($0.route)
            }.map(\.route)
        }
        if let canary = expected.canaryRoute {
            // The canary and its scoped halves (OwnedCanaryRoute), each only when observed with our mark and generation.
            let found = canary.routes.filter { route in
                observed.routes.contains {
                    $0.route == route && $0.identity == canary.identity && $0.hasProtocol2Flag && $0.generation == expected.generation
                }
            }
            if !found.isEmpty {
                owned.canaryRoute = canary
                owned.routes += found
            }
        }
        if let key = expected.dnsKey, key == observed.dnsKey, expected.dns == observed.dns {
            owned.dnsKey = key; owned.dns = expected.dns
        }
        return owned
    }
}
