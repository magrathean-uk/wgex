// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

/// Answers each resolve from a per-call script: pass, fail, or park until released (ignoring cancellation).
private actor ScriptedResolver: ProviderEndpointResolving {
    enum Step { case pass, fail, park }

    private(set) var calls = 0
    private var script: [Int: Step] = [:]
    private var parked: [Int: CheckedContinuation<[PublicKey: Endpoint], any Error>] = [:]

    func script(call: Int, _ step: Step) {
        script[call] = step
    }

    func isParked(_ call: Int) -> Bool {
        parked[call] != nil
    }

    func release(call: Int, failing: Bool = false) {
        guard let continuation = parked.removeValue(forKey: call) else { return }
        if failing {
            continuation.resume(throwing: TunnelError.backendUnavailable)
        } else {
            continuation.resume(returning: [:])
        }
    }

    func resolve(_: TunnelProfile, interfaceIndex _: UInt32?) async throws -> [PublicKey: Endpoint] {
        calls += 1
        let call = calls
        switch script[call] ?? .pass {
        case .pass: return [:]
        case .fail: throw TunnelError.backendUnavailable
        case .park: return try await withCheckedThrowingContinuation { parked[call] = $0 }
        }
    }
}

private final class LogSink: Sendable {
    private let lines = Mutex<[String]>([])
    var all: [String] {
        lines.withLock { $0 }
    }

    func record(_ line: String) {
        lines.withLock { $0.append(line) }
    }
}

private struct PathHarness {
    let clock = TestClock()
    let system: FakeProviderSystem
    let resolver = ScriptedResolver()
    let factory = RecordingEngineFactory()
    let sink = LogSink()
    let controller: ProviderController
    let profile: TunnelProfile

    init() throws {
        system = FakeProviderSystem(clock: clock)
        profile = try GoldenFixture.profile()
        let factory = factory
        let sink = sink
        controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: resolver,
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
            pathFailureLog: { sink.record($0) },
        )
    }

    var engine: FakeEngine {
        factory.engines[factory.engines.count - 1]
    }

    var log: [String] {
        sink.all
    }

    func start() async throws {
        try await controller.startTunnel(profileID: profile.id)
    }

    func path(_ index: UInt32) async throws {
        try await controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: index))
    }

    func handshake() async {
        let at = clock.wallNow
        await engine.emit(.handshakeCompleted(peer: profile.peers[0].publicKey, at: at))
        await eventually { await controller.status.health.lastHandshake == at }
    }

    func expectActive(sourceLocation: SourceLocation = #_sourceLocation) async {
        guard case .active = await controller.status.phase else {
            Issue.record("Not active", sourceLocation: sourceLocation); return
        }
    }
}

/// Lets tasks that are already runnable reach their next suspension; bounded, never wall-clock.
private func drain() async {
    for _ in 0 ..< 2000 {
        await Task.yield()
    }
}

private let bump7 = FakeEngine.Call.bumpSockets(v4: 7, v6: 7)
private let update = FakeEngine.Call.updateEndpoints(count: 0)

/// A path change whose resolve fails still moves the sockets (M2-03; M2-02a VERIFY LOW-3, ADV-VERIFY INFO-2).
@Suite(.timeLimit(.minutes(1)))
private struct ProviderPathFailureTests {
    @Test
    func `a failed resolve still rebinds the sockets, and the same path again retries it`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .fail)
        await #expect(throws: TunnelError.backendUnavailable) { try await h.path(7) }
        var calls = await h.engine.calls
        #expect(calls.contains(bump7))
        #expect(!calls.contains(update))
        #expect(await !h.system.reasserting)
        #expect(await h.system.cancels.isEmpty)
        await h.expectActive()
        // The identical update retries the resolve; this one succeeds, so the endpoints apply and a reassert starts.
        try await h.path(7)
        #expect(await h.resolver.calls == 3)
        calls = await h.engine.calls
        #expect(calls.filter { $0 == bump7 }.count == 2)
        #expect(calls.filter { $0 == update }.count == 1)
        #expect(await h.system.reasserting)
        // A resolved path is not resolved again for an identical update.
        try await h.path(7)
        #expect(await h.resolver.calls == 3)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a resolve that times out still rebinds the sockets`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let change = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        h.clock.advance(10)
        await #expect(throws: TunnelError.timedOut) { try await change.value }
        let calls = await h.engine.calls
        #expect(calls.contains(bump7))
        #expect(!calls.contains(update))
        #expect(await !h.system.reasserting)
        await h.expectActive()
        await h.resolver.release(call: 2)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `an engine error from the rebind after a failed resolve ends the tunnel`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .fail)
        h.factory.faults.arm("bumpSockets", error: EngineError.bind)
        await #expect(throws: TunnelError.backendUnavailable) { try await h.path(7) }
        let failure = TunnelError.engine(code: -5)
        #expect(await h.controller.status.phase == .failed(failure, blockedByPolicy: false, needsSecrets: false))
        #expect(await h.system.cancels == [failure])
        #expect(await h.system.settings.last == .some(nil))
        #expect(await h.engine.isShutDown)
    }

    @Test
    func `a cancelled resolve does nothing`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let change = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        change.cancel()
        await #expect(throws: TunnelError.cancelled) { try await change.value }
        let calls = await h.engine.calls
        #expect(!calls.contains(bump7))
        #expect(!calls.contains(update))
        #expect(await !h.system.reasserting)
        #expect(await h.system.cancels.isEmpty)
        await h.expectActive()
        await h.resolver.release(call: 2)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a failed resolve from before a reload does not rebind the new generation even when its path matches`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let stale = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        try await h.start()
        try await h.path(7)
        let engine = h.engine
        #expect(await engine.calls.filter { $0 == bump7 }.count == 1)
        await h.resolver.release(call: 2, failing: true)
        await #expect(throws: TunnelError.backendUnavailable) { try await stale.value }
        #expect(await engine.calls.filter { $0 == bump7 }.count == 1)
        #expect(await h.system.cancels.isEmpty)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a failed resolve for a superseded path does not rebind to it`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let first = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        try await h.path(8)
        await h.resolver.release(call: 2, failing: true)
        await #expect(throws: TunnelError.backendUnavailable) { try await first.value }
        let calls = await h.engine.calls
        #expect(!calls.contains(bump7))
        #expect(calls.contains(.bumpSockets(v4: 8, v6: 8)))
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a failed resolve that outlives a stop rebinds nothing`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let change = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        await h.controller.stopTunnel(reason: 1)
        await h.resolver.release(call: 2, failing: true)
        _ = await change.result
        #expect(await !h.engine.calls.contains(bump7))
        #expect(await h.system.cancels.isEmpty)
        #expect(await h.controller.status == .idle)
    }

    // MARK: Path stream and log (M2-02b LOW-B)

    @Test
    func `a path from the stream that fails to resolve is logged once and still rebinds`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .fail)
        await h.system.yieldPath(ProviderPath(satisfied: true, interfaceIndex: 7))
        await eventually { await h.engine.calls.contains(bump7) }
        await eventually { !h.log.isEmpty }
        #expect(h.log == ["Path change not applied: endpoint resolution failed"])
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a stop that cancels a resolve from the path stream is not logged as a failure`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        await h.system.yieldPath(ProviderPath(satisfied: true, interfaceIndex: 7))
        await eventually { await h.resolver.isParked(2) }
        await h.controller.stopTunnel(reason: 1)
        await drain()
        #expect(h.log.isEmpty)
        #expect(await !h.engine.calls.contains(bump7))
        await h.resolver.release(call: 2)
    }
}

/// Guards M2-02a relies on that the shipped suite did not pin (M2-02a FIX1-VERIFY LOW-A, ADV-VERIFY LOW-1..3).
@Suite(.timeLimit(.minutes(1)))
private struct ProviderGuardPinTests {
    @Test
    func `a fatal failure forgets the connection, so a later failing start throws without a second cancel`() async throws {
        let h = try PathHarness()
        try await h.start()
        h.factory.faults.arm("up", error: EngineError.state)
        await #expect(throws: TunnelError.engine(code: -8)) { try await h.start() }
        #expect(await h.system.cancels == [.engine(code: -8)])
        h.factory.faults.arm("up", error: EngineError.state)
        await #expect(throws: TunnelError.engine(code: -8)) { try await h.start() }
        #expect(await h.system.cancels.count == 1)
        #expect(await h.system.settings.last == .some(nil))
    }

    @Test
    func `a parked path resolve from before a reload is discarded even when the new path matches`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.resolver.script(call: 2, .park)
        let stale = Task { try await h.path(7) }
        await eventually { await h.resolver.isParked(2) }
        try await h.start()
        try await h.path(7)
        let engine = h.engine
        #expect(await engine.calls.filter { $0 == bump7 }.count == 1)
        await h.resolver.release(call: 2)
        try await stale.value
        #expect(await engine.calls.filter { $0 == bump7 }.count == 1)
        #expect(await engine.calls.filter { $0 == update }.count == 1)
        #expect(await !h.factory.engines[0].calls.contains(update))
        #expect(await h.system.cancels.isEmpty)
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a newer reassert is not cut short by the older timer`() async throws {
        let h = try PathHarness()
        try await h.start()
        try await h.path(7)
        h.clock.advance(50)
        try await h.path(8)
        h.clock.advance(40)
        await drain()
        #expect(await h.system.reasserting)
        h.clock.advance(50)
        await eventually { await !h.system.reasserting }
        await h.expectActive()
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `a fatal event queued behind a lock holder does not cancel once stop was requested`() async throws {
        let h = try PathHarness()
        try await h.start()
        await h.handshake()
        await h.system.setHoldQuiesce(true)
        let sleep = Task { await h.controller.sleep() }
        await eventually { await h.system.quiesceParked == 1 }
        await h.engine.emit(.engine(.deviceClosed(.tunReadError)))
        await drain()
        let stop = Task { await h.controller.stopTunnel(reason: 1) }
        await drain()
        await h.system.releaseQuiesce()
        await sleep.value; await stop.value
        await drain()
        #expect(await h.system.cancels.isEmpty)
        #expect(await h.controller.status == .idle)
    }
}
