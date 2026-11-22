// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

/// Resolver whose calls can be held open (ignoring cancellation) and released on demand.
private actor HeldResolver: ProviderEndpointResolving {
    private(set) var calls = 0
    private var hold = false
    private var pending: [CheckedContinuation<[PublicKey: Endpoint], any Error>] = []

    func setHold(_ value: Bool) {
        hold = value
    }

    func releaseAll() {
        hold = false
        let waiting = pending; pending = []
        for continuation in waiting {
            continuation.resume(returning: [:])
        }
    }

    func resolve(_: TunnelProfile, interfaceIndex _: UInt32?) async throws -> [PublicKey: Endpoint] {
        calls += 1
        guard hold else { return [:] }
        return try await withCheckedThrowingContinuation { pending.append($0) }
    }
}

private struct Harness {
    let clock = TestClock()
    let system: FakeProviderSystem
    let resolver = HeldResolver()
    let factory = RecordingEngineFactory()
    let controller: ProviderController
    let profile: TunnelProfile

    init() throws {
        system = FakeProviderSystem(clock: clock)
        profile = try GoldenFixture.profile()
        let factory = factory
        controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: resolver,
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
    }

    /// The newest engine; every caller has started at least once.
    var engine: FakeEngine {
        factory.engines[factory.engines.count - 1]
    }

    func start() async throws {
        try await controller.startTunnel(profileID: profile.id)
    }

    func handshake(age: TimeInterval = 0) async -> Date {
        let at = clock.wallNow.addingTimeInterval(-age)
        await engine.emit(.handshakeCompleted(peer: profile.peers[0].publicKey, at: at))
        await eventually { await controller.status.health.lastHandshake == at }
        return at
    }

    func expectFailedAndCancelledOnce(_ code: Int32, sourceLocation: SourceLocation = #_sourceLocation) async throws {
        let failure = TunnelError.engine(code: code)
        let phase = await controller.status.phase
        #expect(phase == .failed(failure, blockedByPolicy: false, needsSecrets: false), sourceLocation: sourceLocation)
        #expect(await system.cancels == [failure], sourceLocation: sourceLocation)
        #expect(await system.settings.last == .some(nil), sourceLocation: sourceLocation)
        #expect(await !system.reasserting, sourceLocation: sourceLocation)
        #expect(await engine.isShutDown, sourceLocation: sourceLocation)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ProviderFailurePathTests {
    // MARK: Cancel seam and fatal post-start failures (items 1, 2)

    @Test
    func `device closed cleans up and cancels the tunnel once`() async throws {
        let h = try Harness()
        try await h.start()
        let engine = h.engine
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        await engine.emit(.engine(.socketsBumped(ok: false)))
        await eventually { await !h.system.cancels.isEmpty }
        try await h.expectFailedAndCancelledOnce(-9)
    }

    @Test
    func `failed socket rebind cleans up and cancels the tunnel`() async throws {
        let h = try Harness()
        try await h.start()
        await h.engine.emit(.engine(.socketsBumped(ok: false)))
        await eventually { await !h.system.cancels.isEmpty }
        try await h.expectFailedAndCancelledOnce(-5)
    }

    @Test
    func `config restored and a good rebind are not fatal`() async throws {
        let h = try Harness()
        try await h.start()
        let engine = h.engine
        await engine.emit(.engine(.configRestored))
        await engine.emit(.engine(.socketsBumped(ok: true)))
        _ = await h.handshake()
        #expect(await h.system.cancels.isEmpty)
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        await h.controller.stopTunnel(reason: 1)
    }

    @Test(arguments: ["updateEndpoints", "bumpSockets"] as [FaultInjector.Point])
    func `path change engine failure cleans up and cancels the tunnel`(_ point: FaultInjector.Point) async throws {
        let h = try Harness()
        try await h.start()
        h.factory.faults.arm(point, error: EngineError.bind)
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        try await h.expectFailedAndCancelledOnce(-5)
    }

    @Test(arguments: ["bumpSockets", "forceHandshake"] as [FaultInjector.Point])
    func `wake engine failure cleans up and cancels the tunnel`(_ point: FaultInjector.Point) async throws {
        let h = try Harness()
        try await h.start(); _ = await h.handshake()
        await h.controller.sleep(); h.clock.advance(200)
        h.factory.faults.arm(point, error: EngineError.bind)
        try await h.controller.wake()
        try await h.expectFailedAndCancelledOnce(-5)
    }

    @Test
    func `failed reload cleans up and cancels the tunnel`() async throws {
        let h = try Harness()
        try await h.start()
        h.factory.faults.arm("up", error: EngineError.state)
        await #expect(throws: TunnelError.engine(code: -8)) { try await h.start() }
        #expect(h.factory.engines.count == 2)
        try await h.expectFailedAndCancelledOnce(-8)
    }

    @Test
    func `failed initial start throws without cancelling`() async throws {
        let h = try Harness()
        h.factory.faults.arm("up", error: EngineError.state)
        await #expect(throws: TunnelError.engine(code: -8)) { try await h.start() }
        #expect(await h.system.cancels.isEmpty)
        #expect(await h.system.settings.last == .some(nil))
    }

    @Test
    func `stop after a fatal failure does not cancel again`() async throws {
        let h = try Harness()
        try await h.start()
        await h.engine.emit(.engine(.deviceClosed(.tunReadError)))
        await eventually { await !h.system.cancels.isEmpty }
        await h.controller.stopTunnel(reason: 1)
        #expect(await h.system.cancels.count == 1)
        #expect(await h.controller.status == .idle)
    }

    // MARK: Reload without clearing (item 3)

    @Test
    func `reload applies the new settings over the old without clearing first`() async throws {
        let h = try Harness()
        try await h.start()
        let before = await h.system.settings.count
        try await h.start()
        let added = await h.system.settings.dropFirst(before)
        #expect(added.count == 1)
        #expect(added.allSatisfy { $0 != nil })
        #expect(h.factory.engines.count == 2)
        #expect(await h.factory.engines[0].isShutDown)
        #expect(await h.factory.engines[1].isUp)
        #expect(await h.system.cancels.isEmpty)
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        await h.controller.stopTunnel(reason: 1)
        #expect(await h.system.settings.last == .some(nil))
    }

    // MARK: Resolve outside the lock (item 4)

    @Test
    func `stop is not blocked by a resolve in flight and the late result is discarded`() async throws {
        let h = try Harness()
        try await h.start()
        await h.resolver.setHold(true)
        let change = Task { try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7)) }
        await eventually { await h.resolver.calls == 2 }
        let stop = Task { await h.controller.stopTunnel(reason: 1) }
        await eventually { await h.controller.status == .idle }
        await h.resolver.releaseAll()
        await stop.value
        try await change.value
        let engine = h.engine
        #expect(await !engine.calls.contains(.updateEndpoints(count: 0)))
        #expect(await !engine.calls.contains(.bumpSockets(v4: 7, v6: 7)))
        #expect(await h.system.cancels.isEmpty)
        #expect(await h.controller.status == .idle)
    }

    @Test
    func `a superseded path result is discarded and the latest path is applied`() async throws {
        let h = try Harness()
        try await h.start()
        await h.resolver.setHold(true)
        let first = Task { try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7)) }
        await eventually { await h.resolver.calls == 2 }
        let second = Task { try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 8)) }
        await eventually { await h.resolver.calls == 3 }
        await h.resolver.releaseAll()
        try await first.value; try await second.value
        let calls = await h.engine.calls
        #expect(calls.filter { $0 == .updateEndpoints(count: 0) }.count == 1)
        #expect(!calls.contains(.bumpSockets(v4: 7, v6: 7)))
        #expect(calls.contains(.bumpSockets(v4: 8, v6: 8)))
        await h.controller.stopTunnel(reason: 1)
    }

    // MARK: Reasserting timeout (item 5)

    @Test
    func `wake reasserting times out after 90 seconds and keeps the stale handshake`() async throws {
        let h = try Harness()
        try await h.start()
        let stale = await h.handshake(age: 100)
        await h.controller.sleep(); h.clock.advance(100)
        try await h.controller.wake()
        #expect(await h.system.reasserting)
        h.clock.advance(89)
        await eventually { h.clock.sleeperCount >= 1 }
        #expect(await h.system.reasserting)
        h.clock.advance(1)
        await eventually { await !h.system.reasserting }
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        #expect(await h.controller.status.health.lastHandshake == stale)
        #expect(await h.system.cancels.isEmpty)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `path change reasserting times out after 90 seconds`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await h.system.reasserting)
        h.clock.advance(90)
        await eventually { await !h.system.reasserting }
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a handshake before the timeout clears reasserting and stop leaves no timer`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        _ = await h.handshake()
        #expect(await !h.system.reasserting)
        await h.controller.stopTunnel(reason: 1)
        await eventually { h.clock.sleeperCount == 0 }
    }

    // MARK: Wake only after a recorded sleep (item 6)

    @Test
    func `wake without a recorded sleep does nothing`() async throws {
        let h = try Harness()
        try await h.start(); _ = await h.handshake(age: 200)
        try await h.controller.wake()
        let calls = await h.engine.calls
        #expect(!calls.contains(.bumpSockets(v4: nil, v6: nil)))
        #expect(!calls.contains(.forceHandshake))
        #expect(await !h.system.reasserting)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a duplicate wake does nothing`() async throws {
        let h = try Harness()
        try await h.start(); _ = await h.handshake()
        await h.controller.sleep(); h.clock.advance(30)
        try await h.controller.wake()
        try await h.controller.wake()
        let calls = await h.engine.calls
        #expect(calls.filter { $0 == .bumpSockets(v4: nil, v6: nil) }.count == 1)
        #expect(calls.filter { $0 == .forceHandshake }.count == 1)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `wake after stop does nothing`() async throws {
        let h = try Harness()
        try await h.start()
        await h.controller.sleep()
        await h.controller.stopTunnel(reason: 1)
        try await h.controller.wake()
        #expect(await !h.engine.calls.contains(.bumpSockets(v4: nil, v6: nil)))
        #expect(await h.controller.status == .idle)
    }

    @Test
    func `a sleep from before a reload does not wake the new generation`() async throws {
        let h = try Harness()
        try await h.start()
        await h.controller.sleep(); h.clock.advance(30)
        try await h.start()
        try await h.controller.wake()
        #expect(await !h.engine.calls.contains(.bumpSockets(v4: nil, v6: nil)))
        await h.controller.stopTunnel(reason: 1)
    }
}

/// Overlapping reloads, timer leaks and log text (M2-02a fix pass 1).
@Suite(.timeLimit(.minutes(1)))
private struct ProviderReloadRaceTests {
    // MARK: Overlapping reloads behave like one (ENGINE-03)

    @Test
    func `overlapping reloads where the newest succeeds never clear the settings`() async throws {
        let h = try Harness()
        try await h.start()
        let before = await h.system.settings.count
        await h.resolver.setHold(true)
        let first = Task { try await h.start() }
        await eventually { await h.resolver.calls == 2 }
        // The newer reload cancels the first, which is parked in its resolve; it resolves at once.
        await h.resolver.setHold(false)
        let second = Task { try await h.start() }
        await #expect(throws: TunnelError.cancelled) { try await first.value }
        try await second.value
        await h.resolver.releaseAll()
        let added = await h.system.settings.dropFirst(before)
        #expect(added.map { $0 != nil } == [true])
        #expect(await h.system.cancels.isEmpty)
        #expect(h.factory.engines.count == 2)
        #expect(await h.factory.engines[0].isShutDown)
        #expect(await h.factory.engines[1].isUp)
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        await h.controller.stopTunnel(reason: 1)
        #expect(await h.system.settings.last == .some(nil))
    }

    @Test
    func `overlapping reloads where the newest fails still cancel`() async throws {
        let h = try Harness()
        try await h.start()
        let before = await h.system.settings.count
        await h.resolver.setHold(true)
        let first = Task { try await h.start() }
        await eventually { await h.resolver.calls == 2 }
        await h.resolver.setHold(false)
        h.factory.faults.arm("up", error: EngineError.state)
        let second = Task { try await h.start() }
        await #expect(throws: TunnelError.cancelled) { try await first.value }
        await #expect(throws: TunnelError.engine(code: -8)) { try await second.value }
        await h.resolver.releaseAll()
        // The old settings stay until the second reload's own apply; the only clear comes after it, from the failure.
        let added = await h.system.settings.dropFirst(before)
        #expect(added.map { $0 != nil } == [true, false])
        #expect(h.factory.engines.count == 2)
        try await h.expectFailedAndCancelledOnce(-8)
    }

    @Test
    func `a stop that supersedes a reload still clears the settings once`() async throws {
        let h = try Harness()
        try await h.start()
        let before = await h.system.settings.count
        await h.resolver.setHold(true)
        let reload = Task { try await h.start() }
        await eventually { await h.resolver.calls == 2 }
        await h.controller.stopTunnel(reason: 1)
        await #expect(throws: TunnelError.cancelled) { try await reload.value }
        await h.resolver.releaseAll()
        #expect(await h.system.settings.dropFirst(before).map { $0 != nil } == [false])
        #expect(await h.system.cancels.isEmpty)
        #expect(await h.controller.status == .idle)
        // The next start is an initial start again: a failure throws and does not cancel.
        h.factory.faults.arm("up", error: EngineError.state)
        await #expect(throws: TunnelError.engine(code: -8)) { try await h.start() }
        #expect(await h.system.cancels.isEmpty)
    }

    // MARK: No timer survives a stop or a reload

    @Test
    func `stop while reasserting without a handshake leaves no timer`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await h.system.reasserting)
        await h.controller.stopTunnel(reason: 1)
        #expect(await !h.system.reasserting)
        await eventually { h.clock.sleeperCount == 0 }
    }

    @Test
    func `reload while reasserting leaves no stale timer`() async throws {
        let h = try Harness()
        try await h.start()
        try await h.controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await h.system.reasserting)
        try await h.start()
        #expect(await !h.system.reasserting)
        // Only the new generation's statistics timer remains.
        await eventually { h.clock.sleeperCount == 1 }
        h.clock.advance(90)
        guard case .active = await h.controller.status.phase else { Issue.record("Not active"); return }
        #expect(await h.system.cancels.isEmpty)
        await h.controller.stopTunnel(reason: 1)
    }

    // MARK: Cancellation is not logged as a failure (LOW-3)

    @Test
    func `a cancelled resolve is not logged as a resolution failure`() {
        let failed = "Path change not applied: endpoint resolution failed"
        #expect(ProviderController.pathChangeFailureLog(TunnelError.cancelled, taskCancelled: false) == nil)
        #expect(ProviderController.pathChangeFailureLog(CancellationError(), taskCancelled: false) == nil)
        #expect(ProviderController.pathChangeFailureLog(TunnelError.timedOut, taskCancelled: true) == nil)
        #expect(ProviderController.pathChangeFailureLog(TunnelError.timedOut, taskCancelled: false) == failed)
        #expect(ProviderController.pathChangeFailureLog(TunnelError.backendUnavailable, taskCancelled: false) == failed)
    }
}
