// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// M1-17: guest run 6 notOwned on the first start (D12) and the leaked canary route (D13), on the XNU route model.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6OwnershipTests {
    @Test
    func `D12 the daemon's own MTU change does not refuse the tunnel it created`() async throws {
        let stack = try await ModelStack(drift: .sameIndex)
        _ = try await stack.start()
        #expect(await stack.controller.status.phase == .active(stack.journal.snapshot().generation))
        let recorded = try #require(stack.journal.snapshot().resources.first?.identity)
        #expect(recorded == stack.model.identity(named: "utun9"))
        #expect(stack.model.owned.count == 5)
        // A later path change re-applies the MTU and moves ifi_lastchange again. M1-18: the stamp is no part of the
        // identity, so nothing is adopted and the recorded identity stays the kernel's (was `!= recorded` in M1-17).
        try await stack.controller.configureChangedUnderlay(stack.host.profile, identity: recorded)
        #expect(stack.journal.snapshot().resources.first?.identity == stack.model.identity(named: "utun9"))
        #expect(stack.journal.snapshot().resources.first?.identity == recorded)
        #expect(stack.model.stamp("utun9") == 1002)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `D12 a changed interface index after configure fails closed`() async throws {
        let stack = try await ModelStack(drift: .newIndex(10))
        await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        let status = await stack.controller.status
        #expect(status.protection == .blocked)
        #expect(stack.model.owned.isEmpty)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `D13 a start that fails after the canary is installed removes it in the same rollback`() async throws {
        let stack = try await ModelStack(failingVerification: 2)
        await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        #expect(stack.model.requests.contains { $0.type == RouteOperation.add.rawValue && $0.index == 4 })
        #expect(stack.model.canaries.isEmpty)
        #expect(stack.model.owned.isEmpty)
        #expect(stack.journal.snapshot().resources.isEmpty)
        #expect(await stack.controller.status.protection == .blocked)
        await stack.controller.cancelBackgroundWork()
    }

    @Test(arguments: [false, true])
    func `D13 stop removes the canary after a connected or failed start`(_ failedStart: Bool) async throws {
        let stack = try await ModelStack(failingVerification: failedStart ? 2 : nil)
        if failedStart {
            await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        } else {
            _ = try await stack.start()
            #expect(stack.model.canaries.count == 1)
        }
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        #expect(stack.model.canaries.isEmpty)
        #expect(stack.model.owned.isEmpty)
        await stack.controller.cancelBackgroundWork()
    }

    @Test(arguments: [false, true], [false, true])
    func `D13 crash recovery replay removes a journalled canary present at startup`(
        _ utunVanished: Bool, _ physicalMoved: Bool,
    ) async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        let canary = try await installCanary(h, model: model, router: "192.0.2.254")
        if utunVanished {
            model.attach(h.identity.name, index: 7, seconds: 5000)
        }
        if physicalMoved {
            model.touch("en0")
        }
        // A fresh table and inspector stand in for the restarted daemon reading the persisted checkpoint.
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 456)
        let inspector = NetworkRealityInspector(routes: table, dns: AcceptingDNS(), identities: model)
        let reality = try await inspector.inspect(h.resources)
        let owned = DaemonReconciliation.ownedResources(h.resources, observed: reality)
        // M1-18: the observation fences the canary by en0's name, index and link-layer address, so a moved stamp keeps it
        // observed (was `physicalMoved ? nil : canary` while the stamp was part of the identity).
        #expect(owned.canaryRoute == canary)
        try await inspector.removeOwned(owned)
        #expect(model.canaries.isEmpty)
        #expect(model.owned.count == (utunVanished ? 1 : 0))
    }

    @Test
    func `D13 canary teardown survives a moved physical interface identity but not a changed index`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        _ = try await installCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        model.touch("en0", index: 5)
        try await table.removeCanaryRoute(of: h.generation)
        #expect(model.canaries.count == 1)
        model.touch("en0", index: 4)
        try await table.removeRoutes(of: h.generation)
        #expect(model.owned.isEmpty)
    }

    @Test
    func `D13 install adopts a leaked canary on the same interface and router`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1004807, gateway: "192.0.2.254")
        let canary = try journalCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.count == 1)
        #expect(!model.requests.contains { $0.type == RouteOperation.add.rawValue && $0.index == 4 })
        #expect(try await table.observed(h.resources).map(\.route).contains(canary.route))
        try await table.removeRoutes(of: h.generation)
        #expect(model.owned.isEmpty)
    }

    @Test
    func `D13 an unmarked route for the canary is a verification failure and survives`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1000807, gateway: "192.0.2.254")
        _ = try journalCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        await #expect(throws: DaemonFailure.portNotOwned) { try await table.install(h.resources.routes, generation: h.generation) }
        try await table.removeRoutes(of: h.generation)
        #expect(model.canaries.count == 1)
        #expect(model.canaries.first?.flags == 0x1000807)
        #expect(!model.requests.contains { $0.type == RouteOperation.delete.rawValue && $0.index == 4 })
    }

    @Test
    func `D13 a kernel clone of the canary destination is replaced by the owned route`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1020047, gateway: "192.0.2.254")
        _ = try journalCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.map(\.flags) == [0x1004807])
    }

    @Test(arguments: [false, true])
    func `D13 a canary with a different router or interface is replaced`(_ interfaceChange: Bool) async throws {
        let h = try NetworkPortHarness(), host = try ControllerHarness(), model = DarwinRouteKernelModel()
        _ = try await installCanary(h, model: model, router: "192.0.2.254")
        model.attach("en1", index: 5)
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        let before = model.requests.count
        let controller = TunnelController(
            registry: host.registry, secureInstall: VerifiedSecureInstall(), journal: h.journal, secrets: host.store,
            ports: .init(
                engineFactory: host.ports, routes: table, dns: host.ports, policy: host.ports, resolver: host.ports,
                device: host.ports, verifier: host.ports, reality: host.ports,
            ),
            underlay: .init(
                v4: interfaceChange ? 5 : 4, v6: nil, resolvers: [], interfaceNames: [interfaceChange ? "en1" : "en0"],
                interfaceV4Name: interfaceChange ? "en1" : "en0", ipv4Router: interfaceChange ? "192.0.2.254" : "192.0.2.253",
            ),
            clock: host.clock,
        )
        try await controller.configureChangedUnderlay(host.profile, identity: #require(h.resources.identity))
        let canaries = model.canaries
        #expect(canaries.count == 1)
        #expect(canaries.first?.scope == (interfaceChange ? 5 : 4))
        #expect(canaries.first?.gatewayAddress == (interfaceChange ? "192.0.2.254" : "192.0.2.253"))
        #expect(model.requests.dropFirst(before).allSatisfy { $0.type == RouteOperation.get.rawValue || $0.index != 7 })
        #expect(model.owned.contains { $0.index == 7 })
    }

    @Test
    func `D13 the route socket reports an existing ADD key as a reply, other ADD errors still throw`() async throws {
        let h = try NetworkPortHarness()
        let socket = SystemRouteSocket(operations: .init(open: { 9 }, write: { _, _ in EEXIST }, read: { _ in nil }, close: { _ in }))
        let add = try RouteMessageCodec.build(.add, route: h.route, index: 7, sequence: 3, pid: 100)
        let reply = try await socket.exchange(add)
        #expect(reply.error == EEXIST)
        #expect(RouteMessageCodec.isReply(reply, operation: .add, sequence: 3, pid: 100))
        let get = try RouteMessageCodec.build(.get, route: h.route, index: 7, sequence: 4, pid: 100)
        await #expect(throws: DaemonFailure.hostSystem(EEXIST)) { try await socket.exchange(get) }
    }

    @Test(arguments: RouteOperation.allCases, ["192.0.2.1/32", "2001:db8::1/128", "0.0.0.0/1", "2001:db8::/64"])
    func `D13 host route messages carry no netmask`(_ operation: RouteOperation, _ cidr: String) throws {
        let range = try IPAddressRange(cidr)
        let route = RouteSpec(destination: range.address, prefixLength: range.networkPrefixLength, interfaceName: "utun7")
        let message = try RouteMessageCodec.parse(RouteMessageCodec.build(operation, route: route, index: 7, sequence: 1, pid: 2))
        let host = range.networkPrefixLength == range.bytes.count * 8
        #expect((message.addresses[2] == nil) == host)
        #expect((message.flags & 4 != 0) == host)
        #expect(message.matches(route, index: 7))
    }

    @Test
    func `D12 the device reports the identity after its own change and refuses another index`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        let recorded = model.attach("utun7", index: 7)
        let device = SystemTunnelDevice(identities: model, journal: h.journal)
        #expect(try await device.identity(afterConfiguring: recorded) == recorded)
        let moved = try #require(model.touch("utun7"))
        #expect(try await device.identity(afterConfiguring: recorded) == moved)
        model.touch("utun7", index: 8)
        await #expect(throws: DaemonFailure.portNotOwned) { try await device.identity(afterConfiguring: recorded) }
        await #expect(throws: DaemonFailure.portNotOwned) {
            try await device.identity(afterConfiguring: TunnelIdentity.held("utun99", index: 99))
        }
    }

    #if WGEX_LAB_BUILD
        /// M1-18: the movement line names the failed fence check instead of the stamp (`change Ns`); a moved stamp alone
        /// refuses nothing, so the refusal here is a closed descriptor.
        @Test
        func `D12 Lab diagnostics name the refused check and the interface movement`() async throws {
            let h = try NetworkPortHarness(), model = DarwinRouteKernelModel(), host = try ControllerHarness()
            model.attach(h.identity.name, index: 7)
            try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = model.identity(named: "utun7") }
            model.touch("utun7")
            model.closeDescriptor("utun7")
            let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
            let verifier = NetworkProtectionVerifier(routes: table, dns: AcceptingDNS(), identities: model, policy: host.ports)
            let lines = Mutex<[String]>([])
            let engine = HostEngine(trace: HostTrace(), interfaceName: "utun7")
            await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                await #expect(throws: DaemonFailure.portNotOwned) {
                    try await verifier.verify(ProtectionExpectation(
                        resources: h.journal.snapshot().resources[0], policy: .disconnected, engine: engine,
                    ))
                }
                await #expect(throws: DaemonFailure.portNotOwned) {
                    try await table.install(h.resources.routes, generation: h.generation)
                }
                let factory = SystemDaemonEngineFactory(makeEngine: { _ in NamelessEngine() })
                await #expect(throws: DaemonPortError.notOwned) {
                    try await factory.create(
                        configuration: EngineConfiguration(tun: .createUTun(mtu: 1280), bindInterfaceIndexV4: 1, bindInterfaceIndexV6: 1),
                        generation: .initial,
                    )
                }
            }
            #expect(lines.withLock { $0 } == [
                "ownership: tunnel identity drift",
                "ownership: interface utun7 index 7->7 check descriptor",
                "verifier: unknown",
                "ownership: route interface drift",
                "ownership: interface utun7 index 7->7 check descriptor",
                "ownership: engine interface missing",
            ])
        }
    #endif

    private func journalCanary(_ h: NetworkPortHarness, model: DarwinRouteKernelModel, router: String) throws -> OwnedCanaryRoute {
        let physical = try #require(model.identity(named: "en0"))
        let canary = try OwnedCanaryRoute(identity: physical, router: router)
        try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = model.identity(named: "utun7") }
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = canary; $0.resources[0].routes.append(canary.route) }
        return canary
    }

    private func installCanary(
        _ h: NetworkPortHarness, model: DarwinRouteKernelModel, router: String,
    ) async throws -> OwnedCanaryRoute {
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        let canary = try journalCanary(h, model: model, router: router)
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.count == 1)
        return canary
    }
}
