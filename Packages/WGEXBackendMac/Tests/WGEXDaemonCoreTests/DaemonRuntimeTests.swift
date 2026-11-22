// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct DaemonRuntimeTests {
    @Test
    func `no primary golden permits infrastructure on interfaces that do not yet have a primary`() throws {
        let text = try PacketFilterRenderer.render(
            phase: .error,
            modifiers: .init(canary: .loopback),
            context: PFContext(underlay: PFInterface("lo0"), consoleUID: 0),
        )
        let url = try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
            .appendingPathComponent("PacketFilterGoldens/no-primary.pf")
        #expect(try text == String(contentsOf: url, encoding: .utf8))
        #if WGEX_LAB_BUILD
            var context = try PFContext(underlay: PFInterface("lo0"), consoleUID: 0)
            context.labEscapeHatch = try PFAddress("192.168.64.1")
            let lab = try PacketFilterRenderer.render(phase: .error, modifiers: .init(canary: .loopback), context: context)
            #expect(lab.hasPrefix("pass in quick inet proto tcp from 192.168.64.1"))
        #endif
    }

    @Test
    func `canary selects the available family and no primary uses a loopback blocking probe`() throws {
        let v6 = UnderlaySnapshot(v4: nil, v6: 6, resolvers: [], interfaceNames: ["en0"])
        #expect(PFCanaryFamily.choose(v6) == .ipv6)
        let text = try PacketFilterRenderer.render(
            phase: .error,
            modifiers: PFModifiers(canary: .ipv6),
            context: PFContext(underlay: PFInterface("en0"), consoleUID: 0),
        )
        #expect(text.contains("inet6 proto udp from any to 2001:db8::1 port 9"))
        let empty = UnderlaySnapshot(v4: nil, v6: nil, resolvers: [], interfaceNames: [])
        #expect(PFCanaryFamily.choose(empty) == .loopback)
        let loopback = try PacketFilterRenderer.render(
            phase: .error,
            modifiers: PFModifiers(canary: .loopback),
            context: PFContext(underlay: PFInterface("lo0"), consoleUID: 0),
        )
        #expect(loopback.hasPrefix("block drop out quick on lo0 inet proto udp from any to 127.0.0.2 port 9"))
    }

    @Test(arguments: [
        RecoveryFailureReason.noPrimaryInterface,
        .profileUnavailable,
        .multipleBootProfiles,
        .resolverUnavailable,
        .monitorStartFailed,
    ])
    func `listener precedes reconciliation and bounded retry keeps serving blocked status`(reason: RecoveryFailureReason) async throws {
        let harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) { $0.settings.lockdown = true }
        let trace = HostTrace(), clock = HostClock()
        let runtime = DaemonRuntime(clock: clock)
        let ports = DaemonRuntime.Ports(
            startListener: { try? trace.record("listener") },
            setRecovering: { _ in },
            reconcile: { try trace.record("reconcile"); throw DaemonFailure.startup(reason) },
            startMonitors: {
                if reason == .monitorStartFailed {
                    throw HostTestError.injected
                }
            },
            block: { try? await harness.controller.recoveryFailed($0) },
            shouldRetry: { true },
            shutdown: { try await harness.controller.shutdownCleanly() },
        )
        var sleeps = clock.sleeps.makeAsyncIterator()
        await runtime.run(ports: ports)
        #expect(trace.calls.first == "listener")
        for delay in [5, 15, 60, 60] {
            #expect(await sleeps.next() == .seconds(delay))
            #expect(await harness.controller.status.protection == .blocked)
            #expect(await harness.controller.status.recoveryFailureReason == reason)
            clock.advance(.seconds(delay))
        }
        await runtime.stop()
    }

    @Test(arguments: [false, true])
    func `SIGTERM model keeps intent token and writes clean marker or releases without intent`(intent: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        if !intent {
            try harness.journal.mutate(generation: nil) { $0.intent = nil }
        }
        let replacement = try harness.replacementController()
        let before = harness.trace.calls.count
        try await replacement.shutdownCleanly()
        let calls = Array(harness.trace.calls.dropFirst(before))
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(document.cleanShutdownAt != nil)
        #expect((document.pfToken != nil) == intent)
        #expect(calls.contains("pf.error") == intent)
        #expect(calls.contains("pf.release") == !intent)
    }

    @Test
    func `no primary is blocked until an underlay arrives`() async throws {
        let harness = try ControllerHarness(underlay: UnderlaySnapshot(v4: nil, v6: nil, resolvers: [], interfaceNames: []))
        try await harness.install()
        try harness.journal.mutate(generation: nil) { $0.intent = TunnelIntent(profileID: harness.profile.id, ownerUID: 501) }
        try await harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: harness.profile.id)
        await #expect(throws: DaemonFailure.startup(.noPrimaryInterface)) { try await harness.controller.reconcileAtStartup() }
        #expect(await harness.controller.status.protection == .blocked)
        #expect(await harness.controller.status.recoveryFailureReason == .noPrimaryInterface)
        await harness.controller.updateStartupUnderlay(UnderlayEvent(snapshot: ControllerHarness.underlay, satisfied: true, mtu: 1500))
        try await harness.controller.reconcileAtStartup()
        #expect(await harness.controller.status.protection == .protected)
        #expect(await harness.controller.status.recoveryFailureReason == nil)
    }

    @Test
    func `corrupt profile and multiple boot profiles choose none and remain unprotected`() async throws {
        let harness = try ControllerHarness()
        var first = harness.profile; first.macOptions.startBeforeLogin = true
        var second = try ControllerHarness.makeProfile(); second.macOptions.startBeforeLogin = true
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        for profile in [first, second] {
            try repository.save(RegisteredProfile(
                registration: DaemonProfile(profile: profile, revision: 1),
                ownerUID: 501,
                startBeforeLoginOverride: true,
            ))
        }
        await #expect(throws: DaemonFailure.startup(.multipleBootProfiles)) { try await harness.controller.reconcileAtStartup() }
        #expect(await harness.controller.status.recoveryFailureReason == .multipleBootProfiles)
        #expect(await harness.controller.activeProfileID() == nil)
        #expect(await harness.controller.status.protection == .unprotected)
        try repository.remove(second.id)
        try harness.directory.directory("profiles").replace(first.id.uuidString + ".json", with: Data("invalid".utf8))
        await #expect(throws: DaemonFailure.startup(.profileUnavailable)) { try await harness.controller.reconcileAtStartup() }
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test
    func `boot uniqueness applies at install and override`() async throws {
        let harness = try ControllerHarness()
        var first = harness.profile; first.macOptions.startBeforeLogin = true
        try await harness.registry.installProfile(first, expectedRevision: nil, connectionUID: 501)
        try await harness.registry.setStartBeforeLogin(first.id, enabled: true, connectionUID: 501)
        var second = try ControllerHarness.makeProfile(); second.macOptions.startBeforeLogin = true
        try await harness.registry.installProfile(second, expectedRevision: nil, connectionUID: 501)
        await #expect(throws: DaemonFailure.registryMultipleBootProfiles) {
            try await harness.registry.setStartBeforeLogin(second.id, enabled: true, connectionUID: 501)
        }
    }
}
