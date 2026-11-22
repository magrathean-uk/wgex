// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// M1-19 (guest run 6, full4): the full-tunnel start failed with ENETUNREACH on the route step (D14), its undo failed
/// (D15a) and `wgex down` left a released daemon failed/unknown (D15b). The route model applies XNU's RTM_ADD ifaddr
/// selection and sends the pf evaluation canary as a datagram bound to en0 (DarwinRouteKernelModel, ModelStack).
@Suite(.timeLimit(.minutes(1)))
private struct Guest6FullTunnelTests {
    /// The guest's profile shapes: split (lab dns), v4-only full tunnel blocking IPv6 outside (lab full4) and dual.
    enum Variant: CaseIterable, Sendable { case split, full4, dual }

    private static func profile(_ variant: Variant, base: TunnelProfile) throws -> TunnelProfile {
        var profile = base
        switch variant {
        case .split:
            profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
            profile.peers[0].allowedIPs = try [IPAddressRange("10.77.0.0/24")]
            profile.protection.ipv6Policy = .tunnel
        case .full4:
            profile.interface.addresses = try [IPAddressRange("10.77.0.2/24")]
            profile.peers[0].allowedIPs = try ["0.0.0.0/1", "128.0.0.0/1"].map(IPAddressRange.init)
            profile.protection.ipv6Policy = .blockOutside
        case .dual:
            profile.interface.addresses = try ["10.77.0.2/24", "fd77::2/64"].map(IPAddressRange.init)
            profile.peers[0].allowedIPs = try ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"].map(IPAddressRange.init)
            profile.protection.ipv6Policy = .tunnel
        }
        return profile
    }

    /// A v4-only full tunnel that lets IPv6 outside: its only routes are the IPv4 /1s and the canary.
    fileprivate static func ipv4Only(_ stack: ModelStack) async throws {
        var profile = try Self.profile(.full4, base: stack.host.profile)
        profile.protection.ipv6Policy = .allowOutside
        _ = try await stack.host.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
    }

    private static func key(_ entry: DarwinRouteKernelModel.Entry) -> String {
        let address = (try? IPAddressRange(validatingBytes: entry.destination, prefixLength: entry.destination.count * 8))?.address
        return "\(address ?? "?")/\(entry.prefix.map(String.init) ?? "host")@\(entry.scope)"
    }

    @Test
    func `D14 XNU refuses an IPv6 route on a utun without an IPv6 address, and the canary only needs its router on link`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.enforceReachability()
        model.attach("en0", index: 4); model.attach("utun7", index: 7, generation: h.generation)
        try model.assign([IPAddressRange("10.77.0.2/32")], to: "utun7")
        let canary = try OwnedCanaryRoute(identity: #require(model.identity(named: "en0")), router: "192.0.2.254")
        let v4 = RouteSpec(destination: "0.0.0.0", prefixLength: 1, interfaceName: "utun7")
        let v6 = RouteSpec(destination: "8000::", prefixLength: 1, interfaceName: "utun7")
        try h.journal.mutate(generation: h.generation) {
            $0.resources[0].identity = model.identity(named: "utun7"); $0.resources[0].canaryRoute = canary
            $0.resources[0].routes = [canary.route, v4, h.route, v6]
        }
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install([v4, h.route], generation: h.generation)
        await #expect(throws: DaemonFailure.portSystem(code: EIO)) { try await table.install([v6], generation: h.generation) }
        #expect(model.failedAdds == 1)
        // The scoped canary add fails only while its router is off link on en0; the tunnel's /1 routes play no part.
        await #expect(throws: DaemonFailure.portSystem(code: EIO)) { try await table.install([canary.route], generation: h.generation) }
        try model.assign([IPAddressRange("192.0.2.10/24")], to: "en0")
        try await table.install([canary.route], generation: h.generation)
        try model.assign([IPAddressRange(TunnelController.ipv6RouteAddress)], to: "utun7")
        try await table.install([v6], generation: h.generation)
        #expect(Set(model.owned.map(Self.key)) == ["192.0.2.1/host@4", "0.0.0.0/1@0", "128.0.0.0/1@0", "8000::/1@0"])
        // Under the /1 routes the bound canary has a route only through its scoped host route.
        #expect(try model.boundSend(to: "192.0.2.1", interfaceIndex: 4) == 0)
        try await table.removeCanaryRoute(of: h.generation)
        #expect(try model.boundSend(to: "192.0.2.1", interfaceIndex: 4) == ENETUNREACH)
    }

    @Test
    func `F1 a failed tunnel-route delete leaves the canary in place, measurable, and fails typed`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.enforceReachability()
        model.attach("en0", index: 4); model.attach("utun7", index: 7, generation: h.generation)
        try model.assign([IPAddressRange("192.0.2.10/24")], to: "en0")
        try model.assign([IPAddressRange("10.77.0.2/32")], to: "utun7")
        let canary = try OwnedCanaryRoute(identity: #require(model.identity(named: "en0")), router: "192.0.2.254")
        let v4 = RouteSpec(destination: "0.0.0.0", prefixLength: 1, interfaceName: "utun7")
        // Journalled as the lifecycle records it since M1-19: the canary first, then the tunnel routes.
        try h.journal.mutate(generation: h.generation) {
            $0.resources[0].identity = model.identity(named: "utun7"); $0.resources[0].canaryRoute = canary
            $0.resources[0].routes = [canary.route, v4, h.route]
        }
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.count == 1 && model.owned.count == 3)
        try model.failDeletes(of: "0.0.0.0", error: EPERM)
        await #expect(throws: DaemonFailure.portSystem(code: EIO)) { try await table.removeRoutes(of: h.generation) }
        // The /1 routes stay, and so does the canary: the bound evaluation canary still has its route.
        #expect(model.canaries.count == 1 && model.owned.count == 3)
        #expect(try model.boundSend(to: "192.0.2.1", interfaceIndex: 4) == 0)
        try model.failDeletes(of: "0.0.0.0", error: nil)
        try await table.removeRoutes(of: h.generation)
        #expect(model.owned.isEmpty)
        let deletes = model.requests.filter { $0.type == RouteOperation.delete.rawValue }
            .compactMap { $0.addresses[0].flatMap(RouteMessageCodec.address)?.address }
        #expect(deletes == ["0.0.0.0", "0.0.0.0", "128.0.0.0", "192.0.2.1"])
    }

    @Test
    func `D14 the utun gets an IPv6 address only when IPv6 routes would otherwise have none`() throws {
        let base = try ControllerHarness.makeProfile()
        for variant in Variant.allCases {
            let profile = try Self.profile(variant, base: base)
            let routes = TunnelController.routes(profile, interfaceName: "utun4")
            let addresses = try TunnelController.tunnelAddresses(profile, routes: routes)
            let placeholder = try IPAddressRange(TunnelController.ipv6RouteAddress)
            #expect(addresses == profile.interface.addresses + (variant == .full4 ? [placeholder] : []))
        }
    }

    @Test(arguments: Variant.allCases)
    func `D14 every variant starts protected with the canary installed first and measured blocked`(_ variant: Variant) async throws {
        let stack = try await ModelStack()
        let profile = try Self.profile(variant, base: stack.host.profile)
        _ = try await stack.host.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        let generation = try await stack.start()
        let status = await stack.controller.status
        #expect(status.phase == .active(generation) && status.protection == .protected)
        let adds = stack.model.requests.filter { $0.type == RouteOperation.add.rawValue }
        #expect(adds.first.flatMap { $0.addresses[0].flatMap(RouteMessageCodec.address)?.address } == "192.0.2.1")
        #expect(stack.model.canaries.count == 1 && stack.model.failedAdds == 0)
        let canary = try #require(stack.model.canaries.first)
        #expect(canary.flags & 0x1004006 == 0x1004006 && canary.scope == 4 && canary.gatewayAddress == "192.0.2.254")
        let probes = await stack.policy.probes
        #expect(!probes.isEmpty && probes.allSatisfy { $0 == 0 })
        let resources = await stack.controller.resource(generation)
        #expect(resources.routes.first == resources.canaryRoute?.route)
        let v6Routes = resources.routes.filter { $0.destination.contains(":") }.count
        #expect(v6Routes == (variant == .split ? 0 : 2))
        let v6Addresses = stack.model.addresses(named: "utun9").filter(\.isIPv6).map(\.address)
        #expect(v6Addresses == (variant == .split ? [] : [variant == .dual ? "fd77::2" : "fdf0:7765:7800::1"]))
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `D14 a Mac with a scoped default route on en0 still installs and uses the canary under the full tunnel`() async throws {
        let stack = try await ModelStack()
        try stack.model.seed("0.0.0.0", prefix: 0, scope: 4, index: 4, flags: 0x1000803, gateway: "192.0.2.254")
        let profile = try Self.profile(.full4, base: stack.host.profile)
        _ = try await stack.host.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        let generation = try await stack.start()
        #expect(await stack.controller.status.phase == .active(generation))
        #expect(stack.model.canaries.count == 1)
        #expect(stack.model.entries.contains { $0.prefix == 0 && $0.scope == 4 })
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `D15 a failed canary step leaves no tunnel route, utun address or DNS and keeps the measured blocking policy`() async throws {
        let stack = try await ModelStack()
        try await Self.ipv4Only(stack)
        // en0 loses its address: the scoped canary add has no on-link router (ENETUNREACH).
        try stack.model.removeAddress(IPAddressRange("192.0.2.10/24"), from: "en0")
        await #expect(throws: (any Error).self) { _ = try await stack.start() }
        #expect(stack.model.owned.isEmpty)
        #expect(stack.model.addresses(named: "utun9").isEmpty)
        #expect(await stack.host.ports.dnsItems.isEmpty)
        #expect(stack.journal.snapshot().resources.isEmpty)
        let failed = await stack.controller.status
        #expect(failed.protection == .blocked && failed.recoveryFailureReason == nil && failed.protectionNote == nil)
        #expect(await stack.host.ports.policy == .error)
        #expect(await stack.host.ports.token != nil)
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        let stopped = await stack.controller.status
        #expect(stopped.phase == .idle && stopped.protection == .unprotected && stopped.recoveryFailureReason == nil)
        #expect(await stack.host.ports.policy == .disconnected)
        #expect(await stack.host.ports.token == nil)
    }

    @Test
    func `D15 an unmeasured blocking policy no longer stops the undo; it is measured once the routes are gone`() async throws {
        let stack = try await ModelStack()
        try await Self.ipv4Only(stack)
        try stack.model.failAdds(of: "128.0.0.0", error: ENETUNREACH)
        await stack.policy.failProbesAfterRouteFailure(1)
        await #expect(throws: (any Error).self) { _ = try await stack.start() }
        #expect(stack.model.owned.isEmpty)
        #expect(stack.model.addresses(named: "utun9").isEmpty)
        #expect(stack.journal.snapshot().resources.isEmpty)
        let status = await stack.controller.status
        #expect(status.protection == .blocked && status.recoveryFailureReason == nil && status.protectionNote == nil)
        #expect(await stack.policy.probes.last == 0)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `D15 an undo whose policy stays unmeasured releases every resource and fails as a typed verification failure`() async throws {
        #expect(TunnelController.typedUndoFailure(DaemonFailure(code: .pfCanaryFailed)) as? DaemonFailure == .pfVerification)
        #expect(TunnelController.typedUndoFailure(DaemonFailure.portSystem(code: EPERM)) as? DaemonFailure == .portSystem(code: EPERM))
        let stack = try await ModelStack()
        try await Self.ipv4Only(stack)
        try stack.model.failAdds(of: "128.0.0.0", error: ENETUNREACH)
        await stack.policy.failProbesAfterRouteFailure(.max)
        await #expect(throws: (any Error).self) { _ = try await stack.start() }
        #expect(stack.model.owned.isEmpty)
        #expect(stack.model.addresses(named: "utun9").isEmpty)
        let failed = await stack.controller.status
        #expect(failed.protection == .unknown && failed.protectionNote == .canaryFailed)
        // `wgex down`: the stop's blocking step stays unmeasured, the released daemon ends idle (D15b).
        try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
        let stopped = await stack.controller.status
        #expect(stopped.phase == .idle && stopped.protection == .unprotected)
        #expect(stopped.recoveryFailureReason == nil && stopped.protectionNote == nil)
        #expect(stack.journal.snapshot().resources.isEmpty)
        #expect(await stack.host.ports.token == nil)
    }

    @Test
    func `D15 down after a failed full-tunnel start answers ok through the dispatcher and reports idle`() async throws {
        let stack = try await ModelStack()
        try await Self.ipv4Only(stack)
        try stack.model.failAdds(of: "128.0.0.0", error: ENETUNREACH)
        await stack.policy.failProbesAfterRouteFailure(.max)
        await #expect(throws: (any Error).self) { _ = try await stack.start() }
        let next = Mutex<UInt64>(0), controller = stack.controller
        let dispatcher = DaemonDispatcher(
            service: controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            measureStatus: { try await controller.publicationMeasurement(nextSequence: { next.withLock { $0 += 1; return $0 } }) },
        )
        let transport = InMemoryXPCTransport(
            daemon: dispatcher,
            peer: .init(uid: ControllerHarness.uid, pid: 9, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 10))
        guard case let .status(failed) = try await call(.status) else { Issue.record("Missing status"); return }
        #expect(failed.protection == .unknown && failed.policyEnforcing)
        #expect(try await call(.stop(profileID: stack.host.profile.id, reason: .userRequested)) == .ok)
        guard case let .status(status) = try await call(.status) else { Issue.record("Missing status"); return }
        #expect(status.phase == .idle && status.protection == .unprotected)
        #expect(status.recoveryFailureReason == nil && status.protectionNote == nil && status.activeProfileID == nil)
        #expect(!status.policyEnforcing)
    }
}

#if WGEX_LAB_BUILD
    /// M1-19 item 4: fixed-text Lab lines name the failed route kind with its integer code, the start step, the undo
    /// step and the stop's unmeasured blocking step; a withheld undo failure is logged as a typed one.
    @Suite(.timeLimit(.minutes(1)))
    private struct Guest6FullTunnelLabTests {
        enum Failure: CaseIterable, Sendable { case canary, tunnelRoute }

        @Test(arguments: Failure.allCases)
        func `M1-19 Lab lines name the failed full-tunnel start step`(_ failure: Failure) async throws {
            let stack = try await ModelStack()
            try await Guest6FullTunnelTests.ipv4Only(stack)
            switch failure {
            case .canary: try stack.model.removeAddress(IPAddressRange("192.0.2.10/24"), from: "en0")
            case .tunnelRoute:
                try stack.model.failAdds(of: "128.0.0.0", error: ENETUNREACH)
                await stack.policy.failProbesAfterRouteFailure(.max)
            }
            let lines = Mutex<[String]>([])
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                await #expect(throws: (any Error).self) { _ = try await stack.start() }
                try await stack.controller.stop(profileID: stack.host.profile.id, connectionUID: ControllerHarness.uid)
            }
            let output = lines.withLock { $0 }
            #expect(output.contains("start failed at step: installRoutes"))
            switch failure {
            case .canary:
                #expect(output.contains("route install failed, route: canary code: 51"))
                #expect(!output.contains { $0.hasPrefix("undo failed") || $0.hasPrefix("stop failed") })
            case .tunnelRoute:
                #expect(output.contains("route install failed, route: tunnel ipv4 code: 51"))
                #expect(output.contains("undo failed at step: blocking"))
                #expect(output.contains("stop failed at step: stopBlocking"))
            }
            let pattern = "^(route install failed, route: [a-z0-9 ]+ code: -?[0-9]+|(start|undo|stop) failed at step: [A-Za-z]+)$"
            for line in output where line.hasPrefix("route install") || line.contains(" failed at step: ") {
                #expect(line.range(of: pattern, options: .regularExpression) != nil)
            }
            let fields = DaemonDiagnostics.fields(for: TunnelController.typedUndoFailure(DaemonFailure(code: .pfCanaryFailed)))
            #expect(fields.type == "PacketFilterFailure" && fields.label == "verification" && fields.code == -1)
            #expect(await stack.controller.status.phase == .idle)
        }
    }
#endif
