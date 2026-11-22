// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// M08-T12 (lab EXCL-PORT, M08-T04 job): an app bound to en0 on a listed port got EHOSTUNREACH and nothing reached en0,
/// although pf passes it (ExclusionPortTests). Under the tunnel's /1 routes XNU has no route for a socket bound to en0
/// unless one is scoped to en0 (M1-05 D4), so a tunnel that lists ports owns the scoped /1 halves next to the canary.
@Suite(.timeLimit(.minutes(1)))
private struct PortExclusionRouteTests {
    private static func fullTunnel(_ stack: ModelStack, ports: [String]) async throws {
        var profile = stack.host.profile
        profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
        profile.peers[0].allowedIPs = try ["0.0.0.0/1", "128.0.0.0/1"].map(IPAddressRange.init)
        profile.protection.ipv6Policy = .allowOutside
        profile.exclusions.ports = try ports.map(PortExclusion.init)
        _ = try await stack.host.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
    }

    private static func key(_ entry: DarwinRouteKernelModel.Entry) -> String {
        let address = (try? IPAddressRange(validatingBytes: entry.destination, prefixLength: entry.destination.count * 8))?.address
        return "\(address ?? "?")/\(entry.prefix.map(String.init) ?? "host")@\(entry.scope)"
    }

    @Test
    func `a full tunnel that lists ports gives an en0-bound socket a route to a tunnel destination, and stop removes it`() async throws {
        let stack = try await ModelStack()
        try await Self.fullTunnel(stack, ports: ["1911", "6881-6889/udp"])
        let generation = try await stack.start()
        #expect(await stack.controller.status.phase == .active(generation))
        // Fails before the fix: the bound probe had no route (the lab's EHOSTUNREACH).
        #expect(try stack.model.boundSend(to: "203.0.113.9", interfaceIndex: 4) == 0)
        #expect(try stack.model.boundSend(to: "10.77.0.1", interfaceIndex: 4) == 0)
        #expect(Set(stack.model.owned.map(Self.key)) == [
            "192.0.2.1/host@4", "0.0.0.0/1@4", "128.0.0.0/1@4", "0.0.0.0/1@0", "128.0.0.0/1@0",
        ])
        // The halves go through the physical router; unbound traffic still meets the tunnel's own /1 routes first.
        let halves = stack.model.owned.filter { $0.scope == 4 && $0.prefix == 1 }
        #expect(halves.count == 2 && halves.allSatisfy { $0.gatewayAddress == "192.0.2.254" && $0.flags & 0x1000002 == 0x1000002 })
        let journalled = try #require(stack.journal.snapshot().resources.first)
        #expect(journalled.canaryRoute?.portRoutes == true)
        #expect(Array(journalled.routes.prefix(3)) == journalled.canaryRoute?.routes)
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        #expect(stack.model.owned.isEmpty)
        await stack.controller.cancelBackgroundWork()
    }

    /// M08-T22 (lab FIRST-START, route monitor seq 7): with en0 the primary interface, XNU answered the unscoped RTM_GET
    /// for the tunnel's 0.0.0.0/1 with the en0-scoped half installed just before it, and the start failed with
    /// `ownership: foreign route` at installRoutes (notOwned, backendUnavailable).
    @Test
    func `a full tunnel that lists ports starts, reconciles and stops while en0 is the primary scope`() async throws {
        let stack = try await ModelStack()
        stack.model.setPrimaryScope(4)
        try await Self.fullTunnel(stack, ports: ["1911", "6881-6889/udp"])
        let generation = try await stack.start()
        #expect(await stack.controller.status.phase == .active(generation))
        #expect(Set(stack.model.owned.map(Self.key)) == [
            "192.0.2.1/host@4", "0.0.0.0/1@4", "128.0.0.0/1@4", "0.0.0.0/1@0", "128.0.0.0/1@0",
        ])
        // The tick's reconcile re-verifies every journalled route through the same lookup.
        try await stack.controller.tick()
        #expect(await stack.controller.status.phase == .active(generation))
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        #expect(stack.model.owned.isEmpty)
        await stack.controller.cancelBackgroundWork()
    }

    /// M08-T23 (review note 1): the network-change handler runs the ownership-checked install, not the tick's dump read.
    @Test
    func `a route change with both routes installed reconciles through the scoped reply and adds nothing`() async throws {
        let stack = try await ModelStack()
        stack.model.setPrimaryScope(4)
        try await Self.fullTunnel(stack, ports: ["1911"])
        let generation = try await stack.start()
        let before = stack.model.owned.map(Self.key)
        let adds = { stack.model.requests.filter { $0.type == RouteOperation.add.rawValue }.count }
        let added = adds()
        try await stack.controller.networkChanged(trigger: .route)
        #expect(await stack.controller.status.phase == .active(generation))
        #expect(adds() == added)
        #expect(stack.model.owned.map(Self.key) == before)
        await stack.controller.cancelBackgroundWork()
    }

    /// M08-T23 (review note 2): an unmarked exact unscoped entry is invisible to the dump, so behind the scoped reply it
    /// reads as absent; the add collides, the second lookup is again the scoped reply, and the install is refused.
    @Test
    func `an unmarked foreign unscoped half behind the scoped reply is refused and kept`() async throws {
        let stack = try await ModelStack()
        stack.model.setPrimaryScope(4)
        try stack.model.seed("0.0.0.0", prefix: 1, scope: 0, index: 9, flags: 0x3, gateway: "10.77.0.1")
        try await Self.fullTunnel(stack, ports: ["1911"])
        await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        let foreign = stack.model.entries.filter { $0.flags & 0x4000 == 0 && Self.key($0) == "0.0.0.0/1@0" }
        #expect(foreign.count == 1 && foreign[0].index == 9 && foreign[0].gatewayAddress == "10.77.0.1")
        await stack.controller.cancelBackgroundWork()
    }

    /// M08-T23: an en0-scoped IPv6 half (RTF_IFSCOPE, as the kernel reports it) answers the unscoped lookup; the dump fallback matches ::/1
    /// and 8000::/1 exactly.
    @Test
    func `a dual full tunnel starts and stops when en0 scoped IPv6 halves answer the unscoped lookups`() async throws {
        let stack = try await ModelStack()
        stack.model.setPrimaryScope(4)
        try stack.model.seed("::", prefix: 1, scope: 4, index: 4, flags: 0x1000003, gateway: "fe80::1")
        try stack.model.seed("8000::", prefix: 1, scope: 4, index: 4, flags: 0x1000003, gateway: "fe80::1")
        var profile = stack.host.profile
        profile.interface.addresses = try ["10.77.0.2/24", "fd77::2/64"].map(IPAddressRange.init)
        profile.peers[0].allowedIPs = try ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"].map(IPAddressRange.init)
        profile.protection.ipv6Policy = .tunnel
        profile.exclusions.ports = try ["1911"].map(PortExclusion.init)
        _ = try await stack.host.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        let generation = try await stack.start()
        #expect(await stack.controller.status.phase == .active(generation))
        let unscoped = Set(stack.model.owned.filter { $0.scope == 0 }.map(Self.key))
        #expect(unscoped.isSuperset(of: ["::/1@0", "8000::/1@0", "0.0.0.0/1@0", "128.0.0.0/1@0"]))
        try await stack.controller.networkChanged(trigger: .route)
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        #expect(stack.model.owned.isEmpty)
        #expect(stack.model.entries.count == 2) // the seeded scoped halves stay
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `without ports the full tunnel owns no scoped half and an en0-bound socket still has no route`() async throws {
        let stack = try await ModelStack()
        try await Self.fullTunnel(stack, ports: [])
        _ = try await stack.start()
        #expect(try stack.model.boundSend(to: "203.0.113.9", interfaceIndex: 4) == ENETUNREACH)
        #expect(Set(stack.model.owned.map(Self.key)) == ["192.0.2.1/host@4", "0.0.0.0/1@0", "128.0.0.0/1@0"])
        #expect(stack.journal.snapshot().resources.first?.canaryRoute?.portRoutes == false)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `only the canary host and the two IPv4 halves may carry a scoped router gateway`() throws {
        func build(_ destination: String, _ prefix: UInt8) throws -> Data {
            try RouteMessageCodec.build(
                .add, route: RouteSpec(destination: destination, prefixLength: prefix, interfaceName: "en0"),
                index: 4, sequence: 1, pid: 1, gateway: "192.0.2.254",
            )
        }
        for (destination, prefix) in [("192.0.2.1", UInt8(32)), ("0.0.0.0", 1), ("128.0.0.0", 1)] {
            let message = try RouteMessageCodec.parse(build(destination, prefix))
            #expect(message.flags & 0x1000002 == 0x1000002)
        }
        for (destination, prefix) in [("0.0.0.0", UInt8(0)), ("10.0.0.0", 8), ("128.0.0.0", 2), ("::", 1)] {
            #expect(throws: DaemonFailure.routeInvalidRoute) { try build(destination, prefix) }
        }
    }

    @Test
    func `a canary journalled before the halves decodes without them`() throws {
        let identity = TunnelIdentity(name: "en0", interfaceIndex: 4)
        let canary = try OwnedCanaryRoute(identity: identity, router: "192.0.2.254")
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(canary.withPortRoutes(true))) as? [String: Any])
        object["portRoutes"] = nil
        let decoded = try JSONDecoder().decode(OwnedCanaryRoute.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded == canary && decoded.routes == [canary.route])
        let withHalves = canary.withPortRoutes(true)
        #expect(withHalves != canary && withHalves.routes.count == 3 && withHalves.routes.first == canary.route)
        #expect(try JSONDecoder().decode(OwnedCanaryRoute.self, from: JSONEncoder().encode(withHalves)) == withHalves)
    }
}
