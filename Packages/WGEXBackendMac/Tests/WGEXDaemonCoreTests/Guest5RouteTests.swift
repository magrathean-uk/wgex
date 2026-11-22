// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5RouteTests {
    @Test(arguments: [RouteOperation.get, .delete, .add], [false, true])
    func `D7 real route socket adapter preserves absent reads and idempotent deletes`(
        _ operation: RouteOperation,
        _ ipv6: Bool,
    ) async throws {
        let h = try NetworkPortHarness()
        let socket = SystemRouteSocket(operations: .init(open: { 123 }, write: { _, _ in ESRCH }, read: { _ in nil }, close: { _ in }))
        let route = ipv6 ? RouteSpec(destination: "8000::", prefixLength: 1, interfaceName: "utun7") : h.route
        let data = try RouteMessageCodec.build(operation, route: route, index: 7, sequence: 19, pid: 100)
        if operation == .add {
            await #expect(throws: DaemonFailure.hostSystem(ESRCH)) { try await socket.exchange(data) }
        } else {
            let message = try await socket.exchange(data)
            #expect(message.error == ESRCH)
            #expect(RouteMessageCodec.isReply(message, operation: operation, sequence: 19, pid: 100))
        }
    }

    @Test
    func `D7 cancelled predecessor undo cannot fail because its route is already gone`() async throws {
        let h = try NetworkPortHarness(), identities = FakeRouteKernel()
        await identities.setIdentity(h.identity)
        let socket = SystemRouteSocket(operations: .init(open: { 123 }, write: { _, _ in ESRCH }, read: { _ in nil }, close: { _ in }))
        let routes = RouteTable(journal: h.journal, kernel: socket, identities: identities, pid: 123)
        let rollback = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await routes.removeRoutes(of: h.generation)
        }
        try await rollback.value
    }

    @Test(arguments: [IPv6Policy.blockOutside, .tunnel])
    func `D11 both IPv6 split defaults are installed owned and removed`(_ policy: IPv6Policy) async throws {
        let h = try NetworkPortHarness(), kernel = FakeRouteKernel()
        var profile = try ControllerHarness.makeProfile(); profile.protection.ipv6Policy = policy
        if policy == .tunnel {
            try profile.peers[0].allowedIPs.append(IPAddressRange("::/0"))
        }
        let routes = TunnelController.routes(profile, interfaceName: h.identity.name)
        try h.journal.mutate(generation: h.generation) { $0.resources[0].routes = routes }
        await kernel.setIdentity(h.identity)
        let table = RouteTable(journal: h.journal, kernel: kernel, identities: kernel, pid: 123)
        try await table.install(routes, generation: h.generation)
        let observed = try await table.observed(h.resources)
        #expect(Set(observed.map(\.route)) == Set(routes))
        #expect(observed.contains { $0.route.destination == "::" && $0.route.prefixLength == 1 })
        #expect(observed.contains { $0.route.destination == "8000::" && $0.route.prefixLength == 1 })
        try await table.removeRoutes(of: h.generation)
        #expect(try await table.observed(h.resources).isEmpty)
    }

    @Test
    func `D11 a live enable reference needs exactly one enabled status read`() async throws {
        let journal = PFMemoryJournal(token: "99"), system = PFScriptedSystem(journal: PFMemoryJournal())
        let lifecycle = try PFTokenLifecycle(runner: PFCtl(system: system), journal: journal, bootSession: nil, onExternalRelease: {})
        _ = try await lifecycle.acquire()
        #expect(await system.calls.filter { $0 == ["-s", "info"] }.count == 1)
    }

    @Test
    func `D4 full tunnel journals a scoped canary route alongside tunnel routes`() async throws {
        let h = try ControllerHarness(underlay: UnderlayMonitorModel.snapshot(
            ipv4: ["PrimaryInterface": "en0", "Router": "192.0.2.254"], ipv6: [:],
            indexes: ["en0": 4], resolvers: ["192.0.2.53"],
        ))
        try await h.install(); _ = try await h.start()
        #expect(h.journal.snapshot().resources.flatMap(\.routes).contains {
            $0.destination == "192.0.2.1" && $0.prefixLength == 32 && $0.interfaceName == "en0"
        })
        let routes = h.journal.snapshot().resources.flatMap(\.routes)
        #expect(routes.contains { $0.destination == "::" && $0.prefixLength == 1 })
        #expect(routes.contains { $0.destination == "8000::" && $0.prefixLength == 1 })
        await h.controller.cancelBackgroundWork()
    }

    @Test
    func `D7 notOwned verification failure retries at five seconds without user action`() async throws {
        let h = try ControllerHarness(); try await h.install(); let epoch = try await h.start()
        await #expect(throws: DaemonFailure.portNotOwned) {
            try await h.controller.maintenance { _, _ in throw DaemonFailure.portNotOwned }
        }
        #expect(await h.controller.status.protection == .blocked)
        h.clock.advance(.milliseconds(4999)); try await h.controller.tick()
        #expect(await h.controller.status.phase != .active(epoch))
        h.clock.advance(.milliseconds(1)); try await h.controller.tick()
        #expect(await h.controller.status.phase == .active(epoch))
        #expect(h.clock.now <= .milliseconds(6500))
        await h.controller.cancelBackgroundWork()
    }
}
