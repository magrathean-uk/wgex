// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// The scoped underlay routes the daemon owns on the physical interface, all through its IPv4 router: the blocked
/// evaluation destination (the canary), and for a tunnel that lists local ports (DEC-126) the two scoped /1 halves.
/// Never an endpoint escape: a scoped route is used only by a socket bound to that interface (IP_BOUND_IF), never by
/// unbound traffic, and the packet filter still decides what such a socket may send.
public struct OwnedCanaryRoute: Codable, Sendable, Hashable {
    public let identity: TunnelIdentity
    public let router: String
    /// The scoped 0.0.0.0/1 and 128.0.0.0/1 halves on the physical interface. Under the tunnel's /1 routes XNU finds no
    /// route for a socket bound to en0 unless one is scoped to en0 (M1-05 D4), so without them an app bound to the
    /// physical interface on a listed port fails with EHOSTUNREACH before pf sees it (M08-T12, lab EXCL-PORT). Halves,
    /// not a scoped default: configd may own a scoped default on the same interface, and these never collide with it.
    public let portRoutes: Bool

    public var route: RouteSpec {
        RouteSpec(destination: "192.0.2.1", prefixLength: 32, interfaceName: identity.name)
    }

    /// The scoped halves, empty unless `portRoutes`.
    public var scopedHalves: [RouteSpec] {
        portRoutes ? ["0.0.0.0", "128.0.0.0"].map { RouteSpec(destination: $0, prefixLength: 1, interfaceName: identity.name) } : []
    }

    /// Every underlay route this record owns, the canary first: it is installed first and removed last.
    public var routes: [RouteSpec] {
        [route] + scopedHalves
    }

    public init(identity: TunnelIdentity, router: String, portRoutes: Bool = false) throws {
        guard let address = try? IPAddressRange(router), !address.isIPv6, !router.contains("/"),
              address.bytes.contains(where: { $0 != 0 }), identity.interfaceIndex > 0 else { throw DaemonFailure.routeInvalidRoute }
        self.identity = identity; self.router = address.address; self.portRoutes = portRoutes
    }

    /// The same canary with or without the scoped halves.
    public func withPortRoutes(_ enabled: Bool) -> OwnedCanaryRoute {
        Self(unchecked: identity, router: router, portRoutes: enabled)
    }

    private init(unchecked identity: TunnelIdentity, router: String, portRoutes: Bool) {
        self.identity = identity; self.router = router; self.portRoutes = portRoutes
    }

    private enum CodingKeys: String, CodingKey { case identity, router, portRoutes }

    /// A journal written before M08-T12 has no `portRoutes`: that canary owns its host route alone.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            unchecked: container.decode(TunnelIdentity.self, forKey: .identity),
            router: container.decode(String.self, forKey: .router),
            portRoutes: container.decodeIfPresent(Bool.self, forKey: .portRoutes) ?? false,
        )
    }
}
