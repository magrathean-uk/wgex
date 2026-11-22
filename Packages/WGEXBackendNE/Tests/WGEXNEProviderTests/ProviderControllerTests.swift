// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

private struct Harness {
    let clock: TestClock
    let system: FakeProviderSystem
    let resolver: FakeResolver
    let engine: FakeEngine
    let controller: ProviderController
    let profile: TunnelProfile

    init(delay: TimeInterval = 0, engineFailure: Bool = false) throws {
        clock = TestClock()
        system = FakeProviderSystem(clock: clock, delay: delay)
        resolver = FakeResolver()
        engine = try FakeEngine(configuration: EngineConfiguration(tun: .networkExtension(descriptor: 42)))
        if engineFailure {
            engine.faults.arm("up", error: EngineError.state)
        }
        profile = try GoldenFixture.profile()
        let engine = engine
        controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: resolver,
            clock: clock, platform: .iOS, engineFactory: { configuration in
                #expect(configuration.tun == .networkExtension(descriptor: 42))
                #expect(configuration.mobileQuirks)
                #expect(configuration.processLimits == .constrained)
                return engine
            },
        )
    }

    func start() async throws {
        try await controller.startTunnel(profileID: profile.id)
    }

    func handshake(age: TimeInterval = 0) async {
        let at = clock.wallNow.addingTimeInterval(-age)
        await engine.emit(.handshakeCompleted(peer: profile.peers[0].publicKey, at: at))
        await eventually { await controller.status.health.lastHandshake == at }
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ProviderControllerTests {
    @Test
    func `start configures then up and reason 17 stops down before clearing settings`() async throws {
        let h = try Harness()
        try await h.start()
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        #expect(await h.system.descriptors == 1)
        #expect(await h.engine.calls.count == 2)
        #expect(await h.engine.calls.last == .up)
        await h.controller.stopTunnel(reason: 17)
        #expect(await h.engine.calls.suffix(2) == [.down, .shutdown])
        #expect(await h.system.settings.last == .some(nil))
        #expect(await h.controller.lastStopReason == 17)
        #expect(await h.controller.status == .idle)
    }

    @Test
    func `RT02 ten second settings deadline fails and clears without creating engine`() async throws {
        let h = try Harness(delay: 20)
        let start = Task { try await h.start() }
        await eventually { h.clock.sleeperCount == 2 }
        h.clock.advance(10)
        await #expect(throws: TunnelError.timedOut) { try await start.value }
        #expect(await h.engine.calls.isEmpty)
        #expect(await h.system.descriptors == 0)
        #expect(await h.system.settings.last == .some(nil))
        #expect(await h.controller.status.phase == .failed(.timedOut, blockedByPolicy: false, needsSecrets: false))
    }

    @Test
    func `engine failure tears down every acquired resource`() async throws {
        let h = try Harness(engineFailure: true)
        await #expect(throws: (any Error).self) { try await h.start() }
        #expect(await h.engine.calls.suffix(2) == [.down, .shutdown])
        #expect(await h.system.settings.last == .some(nil))
        guard case .failed = await h.controller.status.phase else { Issue.record("Not failed"); return }
    }

    @Test
    func `cancelled stop still tears down`() async throws {
        let h = try Harness()
        try await h.start()
        let stop = Task { await h.controller.stopTunnel(reason: 1) }
        stop.cancel()
        await stop.value
        #expect(await h.engine.isShutDown)
        #expect(await h.system.settings.last == .some(nil))
    }

    @Test
    func `stop during pending apply cancels start and cannot publish active`() async throws {
        let h = try Harness(delay: 20)
        let start = Task { try await h.start() }
        await eventually { h.clock.sleeperCount == 2 }
        await h.controller.stopTunnel(reason: 17)
        await #expect(throws: TunnelError.cancelled) { try await start.value }
        #expect(await h.controller.status == .idle)
        #expect(await h.engine.calls.isEmpty)
        await eventually { h.clock.sleeperCount == 0 }
    }

    @Test
    func `caller cancellation during apply fails and clears settings`() async throws {
        let h = try Harness(delay: 20)
        let start = Task { try await h.start() }
        await eventually { h.clock.sleeperCount == 2 }
        start.cancel()
        await #expect(throws: TunnelError.cancelled) { try await start.value }
        #expect(await h.system.settings.last == .some(nil))
        await eventually { h.clock.sleeperCount == 0 }
    }

    @Test(arguments: [0.0, 5, 5.001, 60, 130, 200])
    func `sleep never downs and continuous sleep delta controls handshake`(_ seconds: Double) async throws {
        let h = try Harness()
        try await h.start(); await h.handshake()
        await h.controller.sleep()
        #expect(await !h.engine.calls.contains(.down))
        #expect(await h.system.quiesced)
        h.clock.advance(seconds)
        try await h.controller.wake()
        #expect(await h.engine.calls.contains(.forceHandshake) == (seconds > 5))
        #expect(await h.engine.calls.contains(.bumpSockets(v4: nil, v6: nil)))
        #expect(await h.system.reasserting == (seconds > 5))
        await h.handshake()
        #expect(await !h.system.reasserting)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test(arguments: [100.0, 110, 110.001, 120])
    func `wake forces a handshake only beyond 110 seconds of age`(_ age: Double) async throws {
        let h = try Harness()
        try await h.start(); await h.handshake(age: age)
        await h.controller.sleep()
        try await h.controller.wake()
        #expect(await h.engine.calls.contains(.forceHandshake) == (age > 110))
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `aged handshake plus sleep and responder handshake reassert until completion`() async throws {
        let h = try Harness()
        try await h.start(); await h.handshake(age: 100)
        await h.controller.sleep(); h.clock.advance(100)
        try await h.controller.wake()
        #expect(await h.system.reasserting)
        guard case .reasserting(_, .wake) = await h.controller.status.phase else { Issue.record("Not reasserting"); return }
        await h.handshake()
        #expect(await !h.system.reasserting)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `offline over 30 seconds quiesces and recovery resumes and resolves endpoints`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: false))
        await eventually { h.clock.sleeperCount >= 2 }
        h.clock.advance(30)
        #expect(await !h.system.quiesced)
        await eventually { h.clock.sleeperCount >= 1 }
        h.clock.advance(0.01)
        await eventually { await h.system.quiesced }
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await !h.system.quiesced)
        #expect(await h.resolver.queries == [nil, 7])
        #expect(await h.engine.calls.contains(.updateEndpoints(count: 1)))
        #expect(await h.engine.calls.contains(.bumpSockets(v4: 7, v6: 7)))
        #expect(await !h.engine.calls.contains(.forceHandshake))
        #expect(await h.system.settings.compactMap(\.self).count == 1)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `recovery before deadline cancels quiescence`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: false))
        try await h.controller.pathChanged(ProviderPath(satisfied: true))
        h.clock.advance(31)
        #expect(await !h.system.quiesced)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `statistics on request and thirty second tick and subscribed timer only while armed`() async throws {
        let h = try Harness()
        try await h.start()
        _ = try await h.controller.statistics()
        #expect(await h.engine.calls.filter { $0 == .statistics }.count == 1)
        await eventually { h.clock.sleeperCount == 1 }
        h.clock.advance(30)
        await eventually { await h.controller.statisticsTicks == 1 }
        let subscribe = try ProviderCodec.encode(ProviderMessage.subscribeStats(interval: 2))
        let reply = try #require(await h.controller.handle(subscribe))
        #expect(try ProviderCodec.decode(ProviderReply.self, from: reply) == .ok)
        await eventually { h.clock.sleeperCount == 2 }
        h.clock.advance(2)
        await eventually { await h.controller.subscriptionSample() != nil }
        _ = try await h.controller.handle(ProviderCodec.encode(ProviderMessage.unsubscribeStats))
        await eventually { h.clock.sleeperCount == 1 }
        #expect(await h.controller.subscriptionSample() == nil)
        await h.controller.stopTunnel(reason: 1)
        await eventually { h.clock.sleeperCount == 0 }
    }

    @Test
    func `twenty start stop cycles release timers and engine streams`() async throws {
        let clock = TestClock()
        let profile = try GoldenFixture.profile()
        let system = FakeProviderSystem(clock: clock)
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: FakeResolver(),
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        for _ in 0 ..< 20 {
            try await controller.startTunnel(profileID: profile.id)
            await controller.stopTunnel(reason: 1)
            #expect(await controller.status == .idle)
            await eventually { clock.sleeperCount == 0 }
        }
        #expect(factory.engines.count == 20)
        for engine in factory.engines {
            #expect(await engine.isShutDown)
            #expect(await engine.calls.suffix(2) == [.down, .shutdown])
        }
    }

    @Test
    func `lifecycle events are noops during preparation`() async throws {
        let h = try Harness(delay: 20)
        let start = Task { try await h.start() }
        await eventually { h.clock.sleeperCount == 2 }
        await h.controller.sleep(); try await h.controller.wake()
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await !h.system.quiesced)
        #expect(await h.engine.calls.isEmpty)
        #expect(await h.resolver.queries == [nil])
        await h.controller.stopTunnel(reason: 1)
        await #expect(throws: TunnelError.cancelled) { try await start.value }
    }
}
