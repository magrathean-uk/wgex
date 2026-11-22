// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting

@Suite(.timeLimit(.minutes(1)))
private struct BackendStructureTests {
    @Test
    func `reality reads the requested DNS key rather than echoing journal ownership`() async throws {
        let harness = try NetworkPortHarness(), session = FakeDNSSession(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let routes = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        let dns = DNSConfigurator(journal: harness.journal, session: session)
        try await dns.apply(harness.configuration, generation: harness.generation)
        let inspector = NetworkRealityInspector(routes: routes, dns: dns, identities: kernel)
        let matching = try await inspector.inspect(harness.resources)
        #expect(DaemonReconciliation.ownedResources(harness.resources, observed: matching).dnsKey == harness.resources.dnsKey)
        var wrong = harness.resources
        wrong.dnsKey = DNSConfigurator.key(profileID: UUID())
        let observed = try await inspector.inspect(wrong)
        #expect(observed.dnsKey == nil)
        #expect(DaemonReconciliation.ownedResources(wrong, observed: observed).dnsKey == nil)
        #expect(await session.values.count == 1)
    }

    @Test
    func `concurrent maintenance queues behind the lifecycle slot`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let gate = StepGate(point: .verify)
        let trace = HostTrace()
        let first = Task {
            try await harness.controller.maintenance { _, epoch in
                try trace.record("first")
                try await gate.before(.verify, generation: epoch)
            }
        }
        await gate.wait()
        let second = Task {
            try await harness.controller.maintenance { _, _ in try trace.record("second") }
        }
        await gate.release()
        try await first.value; try await second.value
        #expect(trace.calls == ["first", "second"])
    }

    @Test @MainActor
    func `adapter slot removes a cancelled waiter without blocking its successor`() async throws {
        let slot = SerialOperationSlot(), trace = HostTrace()
        let (entered, signal) = AsyncStream.makeStream(of: Void.self)
        try await slot.acquire()
        // Both tasks use this actor; acquire stays on its caller's executor until the queued continuation suspends.
        // Receiving this signal therefore resumes the test only after registration, rather than racing task entry.
        let queued = Task {
            signal.yield(())
            try await slot.acquire(); defer { slot.release() }
            try trace.record("queued")
        }
        for await _ in entered {
            break
        }
        queued.cancel()
        await #expect(throws: CancellationError.self) { try await queued.value }
        #expect(trace.calls.isEmpty)
        slot.release()
        try await slot.acquire()
        slot.release()
    }

    @Test(arguments: [false, true])
    func `adapter slot admits a caller that is already cancelled on entry`(occupied: Bool) async throws {
        let slot = SerialOperationSlot(), trace = HostTrace()
        if occupied {
            try await slot.acquire()
        }
        let rollback = Task {
            while !Task.isCancelled {
                await Task.yield()
            }
            try await slot.acquire(); defer { slot.release() }
            try trace.record("rollback")
        }
        rollback.cancel()
        if occupied {
            for _ in 0 ..< 20 {
                await Task.yield()
            }
            #expect(trace.calls.isEmpty)
            slot.release()
        }
        try await rollback.value
        #expect(trace.calls == ["rollback"])
        try await slot.acquire()
        slot.release()
    }

    @Test
    func `runtime SIGTERM cancels heartbeat and delegates orderly shutdown once`() async throws {
        let clock = HostClock(), trace = HostTrace()
        let runtimeWithClock = DaemonRuntime(clock: clock)
        await runtimeWithClock.run(ports: .init(
            startListener: { try? trace.record("listen") }, setRecovering: { _ in },
            reconcile: {}, startMonitors: {}, block: { _ in }, shouldRetry: { true },
            shutdown: { try trace.record("shutdown") }, heartbeat: { try trace.record("heartbeat") },
        ))
        try await waitForCondition { clock.pendingSleeps.contains(.seconds(5)) }
        clock.advance(.seconds(5))
        try await waitForCondition { trace.calls.contains("heartbeat") }
        try await runtimeWithClock.shutdown()
        clock.advance(.seconds(30))
        #expect(trace.calls == ["listen", "heartbeat", "shutdown"])
        #expect(clock.pendingSleeps.isEmpty)
    }

    @Test
    func `controller start measures canary and a failed canary prevents active protection`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        harness.trace.fail(at: "pf.canary", repeating: true)
        await #expect(throws: (any Error).self) { _ = try await harness.start() }
        #expect(await harness.ports.canaryChecks > 0)
        #expect(await harness.controller.status.protection != .protected)
    }
}
