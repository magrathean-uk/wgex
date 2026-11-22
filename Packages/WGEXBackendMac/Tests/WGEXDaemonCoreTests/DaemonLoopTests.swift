// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct DaemonLoopTests {
    @Test
    func `termination during initial monitor startup prevents reconciliation after shutdown`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .verify), trace = HostTrace()
        try await harness.install(); _ = try await harness.start()
        let controller = try harness.replacementController(), runtime = DaemonRuntime(clock: harness.clock)
        let startup = Task {
            await runtime.run(ports: .init(
                startListener: {}, setRecovering: { _ in },
                reconcile: { try trace.record("reconcile"); try await controller.reconcileAtStartup() },
                startMonitors: { try await gate.before(.verify, generation: .initial) },
                block: { _ in }, shouldRetry: { true },
                shutdown: { try await controller.shutdownCleanly(); try trace.record("shutdown") },
                prepareBlocking: { try await controller.prepareStartupBlocking() },
            ))
        }
        await gate.wait()
        await runtime.terminate(refreshUnderlay: {}, waiting: {})
        let clean = try DaemonJournal(directory: harness.directory).snapshot().cleanShutdownAt
        #expect(clean != nil)
        await gate.release(); await startup.value
        #expect(trace.calls == ["shutdown"])
        #expect(try DaemonJournal(directory: harness.directory).snapshot().cleanShutdownAt == clean)
        let before = harness.trace.calls
        await #expect(throws: CancellationError.self) { try await controller.reconcileAtStartup() }
        #expect(harness.trace.calls == before)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().cleanShutdownAt == clean)
    }

    @Test
    func `recovering runtime keeps status reachable and refuses start before any mutation`() async throws {
        let harness = try ControllerHarness(), runtime = DaemonRuntime(clock: HostClock())
        try await harness.install()
        let fixture = CompositionFixture(harness: harness)
        await runtime.run(ports: .init(
            startListener: {}, setRecovering: { await fixture.composition.dispatcher.setRecovering($0) },
            reconcile: { throw DaemonFailure.startup(.profileUnavailable) }, startMonitors: {},
            block: { _ in }, shouldRetry: { true }, shutdown: {},
        ))
        try await fixture.connect()
        let before = harness.trace.calls
        #expect(try await fixture
            .call(.startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: false)) == .error(.recovering))
        guard case .status = try await fixture.call(.status) else { throw HostTestError.injected }
        #expect(await runtime.isRecovering)
        #expect(harness.trace.calls == before)
        await runtime.stop()
    }

    @Test
    func `lifecycle retry delays verification but never delays the reporting heartbeat`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .verify)
        let trace = HostTrace(), runtime = DaemonRuntime(clock: harness.clock)
        let composition = DaemonComposition(
            controller: harness.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 0,
            statusJournal: StatusPublicationJournal(directory: harness.directory),
            reportingClock: XPCClock(
                now: { Double(harness.clock.now.components.seconds) },
                sleep: { try await harness.clock.sleep(for: $0) },
            ),
        )
        let events = Mutex<[TunnelStatus]>([])
        let transport = InMemoryXPCTransport(daemon: composition.dispatcher, peer: CompositionFixture.peer(501))
        try await transport.connect(callbacks: .init(event: { bytes in
            if let event = try? WireCodec.decode(Event.self, from: bytes), case let .status(status) = event {
                events.withLock { $0.append(status) }
            }
        }))
        _ = try await call(transport, .hello(clientVersion: "test", clientBuild: 11))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        await runtime.run(ports: .init(
            startListener: {}, setRecovering: { await composition.dispatcher.setRecovering($0) },
            reconcile: {}, startMonitors: {}, block: { _ in }, shouldRetry: { true }, shutdown: {},
        ))
        let loop = Task {
            await runtime.runMainLoop(ports: .init(
                retryLifecycle: {
                    try? trace.record("retry")
                    try? await gate.before(.verify, generation: .initial)
                },
                tick: { try trace.record("tick") }, failure: { _ in },
            ))
        }
        try await waitForCondition { harness.clock.pendingSleeps.filter { $0 == .seconds(5) }.count == 2 }
        harness.clock.advance(.seconds(5))
        await gate.wait()
        try await waitForCondition { events.withLock { $0.count == 1 } }
        #expect(trace.calls == ["retry"])
        try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(5)) }
        harness.clock.advance(.seconds(5))
        try await waitForCondition { events.withLock { $0.count == 2 } }
        #expect(trace.calls == ["retry"])
        #expect(events.withLock { $0[0].sequence < $0[1].sequence })
        await gate.release()
        try await waitForCondition { trace.calls.contains("tick") }
        loop.cancel(); await loop.value
        await runtime.stop(); await composition.dispatcher.stopHeartbeat(); await transport.invalidate()
    }

    @Test
    func `SIGTERM retries blocking shutdown on the injected five second cadence`() async throws {
        let clock = HostClock(), trace = HostTrace(), runtime = DaemonRuntime(clock: clock)
        await runtime.run(ports: .init(
            startListener: {}, setRecovering: { _ in }, reconcile: {}, startMonitors: {}, block: { _ in },
            shouldRetry: { true }, shutdown: {
                try trace.record("shutdown")
                if trace.calls.filter({ $0 == "shutdown" }).count == 1 {
                    throw HostTestError.injected
                }
            },
        ))
        let termination = Task {
            await runtime.terminate(
                refreshUnderlay: { try? trace.record("underlay") },
                waiting: { try? trace.record("waiting") },
            )
        }
        try await waitForCondition { clock.pendingSleeps.contains(.seconds(5)) }
        #expect(trace.calls == ["underlay", "shutdown", "waiting"])
        clock.advance(.seconds(5))
        await termination.value
        #expect(trace.calls == ["underlay", "shutdown", "waiting", "underlay", "shutdown"])
    }

    private func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }
}
