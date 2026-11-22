// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct ControllerMonitoringTests {
    @Test(arguments: [false, true])
    func `wake never downs engine bumps sockets and reasserts until handshake`(responder: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        if responder {
            var profile = harness.profile; profile.peers[0].endpoint = nil
            try await harness.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        }
        let generation = try await harness.start()
        let offset = harness.trace.calls.count
        try await harness.controller.powerChanged(.sleep)
        harness.clock.advance(.seconds(6))
        try await harness.controller.powerChanged(.wake)
        let calls = Array(harness.trace.calls.dropFirst(offset))
        #expect(calls.contains("engine.bump")); #expect(calls.contains("engine.handshake")); #expect(!calls.contains("engine.down"))
        #expect(await harness.controller.status.phase == .reasserting(generation, reason: .wake))
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.rx(at: harness.clock.wallNow), generation: generation)
        #expect(await harness.controller.status.phase == .reasserting(generation, reason: .wake))
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: generation)
        #expect(await harness.controller.status.phase == .active(generation))
    }

    @Test
    func `wake closes an expired captive window and path changes cannot reinstall routes inside a window`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 10, connectionUID: ControllerHarness.uid)
        let offset = harness.trace.calls.count
        try await harness.controller.pathChanged(ControllerHarness.underlay, satisfied: true)
        #expect(!harness.trace.calls.dropFirst(offset).contains("routes.install"))
        #expect(await harness.ports.dnsItems.isEmpty)
        try await harness.controller.powerChanged(.sleep)
        harness.clock.advance(.seconds(11))
        try await harness.controller.powerChanged(.wake)
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(harness.trace.calls.dropFirst(offset).contains("routes.install"))
    }

    @Test
    func `captive open extends once with engine alive and rejects another extension without closing protection`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 10, connectionUID: ControllerHarness.uid)
        harness.clock.advance(.seconds(2))
        try await harness.controller.openCaptiveWindow(seconds: 20, connectionUID: ControllerHarness.uid)
        #expect(harness.journal.snapshot().captiveWindow?.extended == true)
        await #expect(throws: DaemonFailure.captiveAlreadyExtended) {
            try await harness.controller.openCaptiveWindow(seconds: 30, connectionUID: ControllerHarness.uid)
        }
        #expect(!harness.trace.calls.contains("engine.down"))
        try await harness.controller.closeCaptiveWindow()
    }

    @Test(arguments: [false, true])
    func `logout retains intent and secrets stops ordinary tunnels and preserves lockdown`(lockdown: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install()
        if lockdown {
            var settings = MacGlobalSettings.defaults; settings.lockdown = true
            try await harness.controller.setGlobalSettings(settings)
        }
        _ = try await harness.start()
        try await harness.controller.consoleUserChanged(nil)
        #expect(harness.journal.snapshot().intent?.profileID == harness.profile.id)
        #expect(harness.journal.snapshot().loginSuspended == true)
        #expect(harness.journal.snapshot().resources.isEmpty)
        #expect(await harness.controller.status.protection == (lockdown ? .blocked : .unprotected))
        let bundle = try await harness.store.loadBundle(profileID: harness.profile.id)
        #expect(bundle.count > 0)
        try await harness.controller.consoleUserChanged(ControllerHarness.uid)
        #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == 1)
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == 1)
        _ = try await harness.controller.start(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(harness.journal.snapshot().loginSuspended == false)
    }

    @Test
    func `route and configd notifications repair owned routes and DNS through controller serial slot`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let offset = harness.trace.calls.count
        try await harness.controller.networkChanged(trigger: .route)
        #expect(harness.trace.calls.dropFirst(offset).contains("routes.install"))
        #expect(harness.trace.calls.dropFirst(offset).contains("dns.apply"))
        #expect(harness.trace.calls.dropFirst(offset).contains("verify"))
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `underlay changes apply recomputed MTU and bind sockets before restoring routes`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let offset = harness.trace.calls.count
        try await harness.controller.networkChanged(
            trigger: .configuration, underlay: UnderlayEvent(snapshot: ControllerHarness.underlay, satisfied: true, mtu: 1400),
        )
        #expect(await harness.ports.deviceMTUs.last == 1320)
        #expect(harness.trace.calls.contains("engine.bump"))
        #expect(harness.trace.calls.filter { $0 == "routes.install" }.count >= 2)
        let calls = Array(harness.trace.calls.dropFirst(offset))
        #expect(try #require(calls.firstIndex(of: "pf.endpoints")) < #require(calls.firstIndex(of: "resolver.resolve")))
    }

    @Test
    func `start before login tunnel survives console logout`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        try await harness.registry.setStartBeforeLogin(harness.profile.id, enabled: true, connectionUID: ControllerHarness.uid)
        let generation = try await harness.start()
        try await harness.controller.consoleUserChanged(nil)
        #expect(await harness.controller.status.phase == .active(generation))
        #expect(!harness.trace.calls.contains("engine.down"))
        #expect(harness.journal.snapshot().loginSuspended != true)
    }

    @Test(arguments: [false, true])
    func `an unavailable address family never leaves engine sockets unbound`(ipv6Only: Bool) async throws {
        let underlay = UnderlaySnapshot(
            v4: ipv6Only ? nil : 4, v6: ipv6Only ? 6 : nil,
            resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"],
        )
        let harness = try ControllerHarness(underlay: underlay)
        try await harness.install(); _ = try await harness.start()
        let configuration = try #require(await harness.ports.configurations.first)
        #expect(configuration.bindInterfaceIndexV4 == (ipv6Only ? 6 : 4))
        #expect(configuration.bindInterfaceIndexV6 == (ipv6Only ? 6 : 4))
    }

    @Test
    func `daemon monitor wiring consumes fake power and login streams and stops cleanly`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let routes = FakeRouteMonitor(), underlay = FakeUnderlayMonitor(), power = FakePowerMonitor(), login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: harness.controller, routes: routes, underlay: underlay, power: power, login: login,
            ownPID: 123, clock: harness.clock, readUnderlay: { UnderlayEvent(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        let statuses = await harness.controller.statusUpdates()
        power.send(.wake)
        await advanceDebounce(harness.clock)
        for await status in statuses {
            if case .reasserting = status.phase {
                break
            }
        }
        login.send(consoleUID: nil)
        await advanceDebounce(harness.clock)
        for await status in statuses {
            if case .idle = status.phase {
                break
            }
        }
        #expect(harness.journal.snapshot().loginSuspended == true)
        await monitoring.stop()
        #expect(await harness.controller.protectionFailureReason == nil)
    }

    @Test
    func `unexpected notification stream termination makes protection unknown`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let routes = FakeRouteMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: harness.controller, routes: routes, underlay: FakeUnderlayMonitor(), power: FakePowerMonitor(),
            login: FakeLoginSessionMonitor(), ownPID: 123, clock: harness.clock,
            readUnderlay: { UnderlayEvent(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        let statuses = await harness.controller.statusUpdates()
        routes.stop()
        for await status in statuses where status.protection == .unknown {
            break
        }
        #expect(await harness.controller.status.protection == .unknown)
        await monitoring.stop()
    }

    private func advanceDebounce(_ clock: HostClock) async {
        for _ in 0 ..< 10000 where !clock.pendingSleeps.contains(.milliseconds(500)) {
            await Task.yield()
        }
        clock.advance(.milliseconds(500))
    }
}
