// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct Guest5CanaryRouteTests {
    @Test
    func `router only change preserves tunnel routes in the fake kernel`() async throws {
        let h = try NetworkPortHarness(), host = try ControllerHarness(), kernel = FakeRouteKernel()
        let physical = TunnelIdentity(name: "en0", interfaceIndex: 4, linkAddress: "02:00:5e:00:00:04")
        await kernel.setIdentity(h.identity); await kernel.setIdentity(physical)
        let table = RouteTable(journal: h.journal, kernel: kernel, identities: kernel, pid: 123)
        let old = try OwnedCanaryRoute(identity: physical, router: "192.0.2.254")
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = old; $0.resources[0].routes.append(old.route) }
        try await table.install(h.resources.routes, generation: h.generation)
        let before = await kernel.requests.count
        let controller = TunnelController(
            registry: host.registry, secureInstall: VerifiedSecureInstall(), journal: h.journal, secrets: host.store,
            ports: .init(
                engineFactory: host.ports,
                routes: table,
                dns: host.ports,
                policy: host.ports,
                resolver: host.ports,
                device: host.ports,
                verifier: host.ports,
                reality: host.ports,
            ),
            underlay: .init(v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"], interfaceV4Name: "en0", ipv4Router: "192.0.2.253"),
            clock: host.clock,
        )
        try await controller.configureChangedUnderlay(host.profile, identity: h.identity)
        let mutations = await kernel.requests.dropFirst(before).filter { $0.type == 1 || $0.type == 2 }
        #expect(mutations.count == 2)
        #expect(mutations.allSatisfy { $0.index == 4 })
        #expect(h.resources.routes == [h.route, old.route])
        #expect(h.resources.canaryRoute?.router == "192.0.2.253")
        #expect(try await table.observed(h.resources).count == 2)
    }

    @Test
    func `D4 ENETUNREACH is a sent canary verification failure and never a pass`() async throws {
        let journal = PFMemoryJournal(), count = Mutex(0)
        let system = PFScriptedSystem(journal: journal)
        let policy = try PolicyEnforcer(
            runner: PFCtl(system: system),
            journal: journal,
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
            canaryProbe: {
                count.withLock { $0 += 1 }; throw DaemonFailure.hostSystem(ENETUNREACH)
            },
        )
        await #expect(throws: DaemonFailure(code: .pfCanaryFailed)) { try await policy.apply(.error) }
        #expect(count.withLock { $0 } == 1)
        #expect(await policy.verification() == .unknown)
    }

    @Test(arguments: [false, true])
    func `D4 scoped canary ownership survives install verify absent lookup and recovery`(_ preexisting: Bool) async throws {
        let h = try NetworkPortHarness(), kernel = FakeRouteKernel()
        let physical = TunnelIdentity(name: "en0", interfaceIndex: 4, linkAddress: "02:00:5e:00:00:04")
        await kernel.setIdentity(h.identity); await kernel.setIdentity(physical)
        let table = RouteTable(journal: h.journal, kernel: kernel, identities: kernel, pid: 123)
        let canary = try #require(await table.canaryRoute(underlay: .init(
            v4: 4, v6: nil, resolvers: [], interfaceNames: ["en0"], interfaceV4Name: "en0", ipv4Router: "192.0.2.254",
        )))
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = canary; $0.resources[0].routes.append(canary.route) }
        if preexisting {
            let data = try RouteMessageCodec.build(.add, route: canary.route, index: 4, sequence: 1, pid: 123, gateway: canary.router)
            try await kernel.seed(RouteMessageCodec.parse(data))
        }
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(try await table.observed(h.resources).count == 2)
        let message = try #require(await kernel.requests.first { $0.index == 4 })
        #expect(message.flags & 0x1000002 == 0x1000002)
        #expect(message.hasOwnershipMark)
        await kernel.eraseAll()
        #expect(try await table.observed(h.resources).isEmpty)
        await kernel.failNextGet(.portSystem(code: ENETUNREACH))
        await #expect(throws: DaemonFailure.portSystem(code: ENETUNREACH)) {
            try await table.install(h.resources.routes, generation: h.generation)
        }
        #expect(try await table.observed(h.resources).isEmpty)
        try await table.install(h.resources.routes, generation: h.generation)
        // A vanished/reused utun must not strand the separately fenced underlay route.
        await kernel.setIdentity(.held(h.identity.name, index: 7))
        let observed = try await table.observed(h.resources)
        let owned = DaemonReconciliation.ownedResources(
            h.resources,
            observed: .init(identity: nil, routes: observed, dnsKey: nil, dns: nil),
        )
        #expect(owned.canaryRoute == canary)
        try await table.removeRoutes(of: h.generation)
        #expect(try await table.observed(h.resources).isEmpty)
        try await table.removeRoutes(of: h.generation)
    }

    /// M1-17 N7 (orchestrator decision): a route carrying our mark in the canary's own shape is our leak and is replaced
    /// whatever its router; an unmarked route with another gateway is still never adopted or deleted.
    @Test(arguments: [false, true])
    func `D4 foreign scoped gateway is never adopted or deleted`(_ marked: Bool) async throws {
        let h = try NetworkPortHarness(), kernel = FakeRouteKernel()
        let physical = TunnelIdentity(name: "en0", interfaceIndex: 4, linkAddress: "02:00:5e:00:00:04")
        await kernel.setIdentity(physical); await kernel.setIdentity(h.identity)
        let canary = try OwnedCanaryRoute(identity: physical, router: "192.0.2.254")
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = canary; $0.resources[0].routes = [canary.route] }
        var data = try Array(RouteMessageCodec.build(.add, route: canary.route, index: 4, sequence: 1, pid: 999, gateway: "192.0.2.253"))
        if !marked {
            RouteMessageCodec.put(0x1000807, at: 8, into: &data)
        }
        try await kernel.seed(RouteMessageCodec.parse(Data(data)))
        let table = RouteTable(journal: h.journal, kernel: kernel, identities: kernel, pid: 123)
        if marked {
            try await table.install(h.resources.routes, generation: h.generation)
            #expect(await kernel.requests.filter { $0.type == 2 }.count == 1)
            #expect(try await table.observed(h.resources).map(\.route) == [canary.route])
        } else {
            await #expect(throws: DaemonFailure.portNotOwned) { try await table.install(h.resources.routes, generation: h.generation) }
            try await table.removeRoutes(of: h.generation)
            #expect(await kernel.requests.allSatisfy { $0.type != 2 })
        }
    }

    @Test(arguments: [false, true], [IPv6Policy.blockOutside, .tunnel, .allowOutside])
    func `D4 every policy blocks the scoped canary before LAN exemptions`(_ allowLAN: Bool, _ ipv6: IPv6Policy) throws {
        let rules = try PacketFilterRenderer.rules(
            phase: .connected,
            modifiers: .init(allowLAN: allowLAN, ipv6Policy: ipv6),
            context: .init(
                underlay: PFInterface("en0"), tunnel: PFInterface("utun7"), lanSubnets: [IPAddressRange("192.0.2.0/24")], consoleUID: 501,
            ),
        )
        let canary = try #require(rules.firstIndex { $0.label == PacketFilterRenderer.canaryLabel })
        #expect(rules[canary].action == .block)
        #expect(rules[canary].destination == .literal("192.0.2.1"))
        #expect(rules.prefix(canary).allSatisfy { $0.interface?.name != "en0" })
    }
}
