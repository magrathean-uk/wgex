// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct ControllerRecoveryTests {
    @Test(arguments: [false, true])
    func `kill nine host model replaces connected policy first then resumes intent or requests secrets`(missing: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install(); let original = try await harness.start()
        if missing {
            try await harness.store.deleteBundle(profileID: harness.profile.id)
        }
        let foreign = RouteSpec(destination: "198.51.100.0", prefixLength: 24, interfaceName: "utun-foreign")
        await harness.ports.setForeign([foreign])
        let offset = harness.trace.calls.count
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        let calls = Array(harness.trace.calls.dropFirst(offset))
        #expect(calls.first == "pf.error")
        #expect(calls.firstIndex(of: "pf.error") ?? 99 < calls.firstIndex(of: "reality.inspect") ?? 0)
        #expect(await harness.ports.foreignRoutes == [foreign])
        if missing {
            #expect(await replacement.status.phase == .failed(.secretsUnavailable, blockedByPolicy: true, needsSecrets: true))
            #expect(await harness.ports.policy == .error)
        } else {
            let epoch = await replacement.currentGeneration
            #expect(epoch > original)
            #expect(await replacement.status.phase == .active(epoch))
            #expect(await harness.ports.token == "host-fake-token")
            // The fresh controller's journal, rather than the original in-memory snapshot, is authoritative.
            #expect(try DaemonJournal(directory: harness.directory).snapshot().resources.map(\.generation) == [epoch])
        }
    }

    @Test
    func `a failed checkpoint still attempts secret retirement and reports incomplete teardown`() async throws {
        let harness = try ControllerHarness(gate: StepGate(point: .deleteSecrets, failing: true))
        try await harness.install(); _ = try await harness.start()
        await #expect(throws: DaemonFailure.controllerOperationFailed) {
            try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        }
        #expect(harness.journal.snapshot().pendingSecretDeletions.isEmpty)
        #expect(await harness.controller.status.protection == .unknown)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(try DaemonJournal(directory: harness.directory).snapshot().pendingSecretDeletions.isEmpty)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }

    @Test
    func `start before login is restored from registered profile and store`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        var profile = harness.profile; profile.macOptions.startBeforeLogin = true
        try await harness.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
        try await harness.registry.setStartBeforeLogin(profile.id, enabled: true, connectionUID: ControllerHarness.uid)
        try await harness.journal.mutate(generation: harness.controller.currentGeneration) { $0.intent = nil }
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(await replacement.status.protection == .protected)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().intent?.profileID == profile.id)
    }

    @Test
    func `expired captive window closes before intended up restart`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 20, connectionUID: ControllerHarness.uid)
        #expect(await harness.ports.routeItems.isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        await harness.controller.cancelBackgroundWork()
        harness.clock.advance(.seconds(30))
        let offset = harness.trace.calls.count
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(document.captiveWindow == nil)
        #expect(document.entries.contains { $0.step == .closeCaptive && $0.action == .didApply })
        #expect(harness.trace.calls.dropFirst(offset).first == "pf.error")
        #expect(await replacement.status.protection == .protected)
    }

    @Test
    func `lockdown persists and keeps the token across explicit disconnect and restart`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        var settings = MacGlobalSettings.defaults; settings.lockdown = true; settings.allowLAN = false
        try await harness.controller.setGlobalSettings(settings)
        _ = try await harness.start()
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
        #expect(await harness.ports.policy == .lockdown)
        #expect(harness.journal.snapshot().pfToken != nil)
        #expect(await harness.ports.modifiers.last?.allowLAN == false)
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(await replacement.status.protection == .blocked)
        #expect(await harness.ports.policy == .lockdown)
    }

    @Test
    func `captive close restores blocking before routes DNS and verified connected policy`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 10, connectionUID: ControllerHarness.uid)
        let offset = harness.trace.calls.count
        try await harness.controller.closeCaptiveWindow()
        let calls = Array(harness.trace.calls.dropFirst(offset))
        #expect(calls == ["pf.error", "routes.install", "dns.apply", "pf.connected", "verify"])
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test(arguments: [false, true], [false, true])
    func `ownership requires matching identity generation route and protocol tag`(identityMatches: Bool, protocolTag: Bool) {
        let identity = TunnelIdentity.held("utun-test", index: 99)
        let foreign = TunnelIdentity.held("utun-test", index: 99)
        let route = RouteSpec(destination: "0.0.0.0", prefixLength: 1, interfaceName: identity.name)
        var expected = GenerationResources(generation: .initial)
        expected.identity = identity; expected.routes = [route]
        let observed = ObservedDaemonRoute(
            route: route,
            identity: identityMatches ? identity : foreign,
            generation: .initial,
            hasProtocol2Flag: protocolTag,
        )
        let snapshot = DaemonRealitySnapshot(identity: identityMatches ? identity : foreign, routes: [observed], dnsKey: nil, dns: nil)
        let owned = DaemonReconciliation.ownedResources(expected, observed: snapshot)
        #expect(owned.routes == (identityMatches && protocolTag ? [route] : []))
        let stale = ObservedDaemonRoute(route: route, identity: identity, generation: .initial.next(), hasProtocol2Flag: true)
        let differentGeneration = DaemonRealitySnapshot(identity: identity, routes: [stale], dnsKey: nil, dns: nil)
        #expect(DaemonReconciliation.ownedResources(expected, observed: differentGeneration).routes.isEmpty)
    }

    @Test
    func `foreign routes and reused interface names are left untouched by identity reconciliation`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        let generation = await harness.controller.currentGeneration
        let foreign = RouteSpec(destination: "0.0.0.0", prefixLength: 1, interfaceName: "utun-test")
        await harness.ports.setForeign([foreign])
        // A different descriptor represents reuse; the fake reality adapter requires all identity fields to match.
        try harness.journal.mutate(generation: generation) {
            $0.resources[0].identity = TunnelIdentity.held("utun-test", index: 100)
            $0.intent = nil
        }
        await harness.controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(await harness.ports.foreignRoutes == [foreign])
        #expect(await harness.ports.routeItems[generation] != nil)
    }
}
