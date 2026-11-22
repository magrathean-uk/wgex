// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXPolicy

private final class ReplayFailureFlag: Sendable {
    let value = Mutex(false)
    func arm() {
        value.withLock { $0 = true }
    }

    func take() -> Bool {
        value.withLock { let armed = $0; $0 = false; return armed }
    }

    var armed: Bool {
        value.withLock { $0 }
    }
}

private final class ReplayFailOnceJournal: DaemonJournalling {
    let base: DaemonJournal
    let flag: ReplayFailureFlag
    init(base: DaemonJournal, flag: ReplayFailureFlag) {
        self.base = base; self.flag = flag
    }

    func snapshot() -> DaemonJournalDocument {
        base.snapshot()
    }

    func allocate(intent: TunnelIntent?, deletingSecretsOf: UUID?) throws -> Generation {
        if flag.take() {
            throw HostTestError.injected
        }
        return try base.allocate(intent: intent, deletingSecretsOf: deletingSecretsOf)
    }

    func mutate(generation: Generation?, _ body: (inout DaemonJournalDocument) throws -> Void) throws {
        try base.mutate(generation: generation, body)
    }
}

/// Suspends exactly one secure-install status read, modelling a slow await inside the controller.
private actor ReplaySecureGate {
    private var armed = false
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var blocked = false
    func arm() {
        armed = true
    }

    func pass() async {
        guard armed else { return }
        armed = false; blocked = true
        await withCheckedContinuation { waiter = $0 }
    }

    func release() {
        waiter?.resume(); waiter = nil
    }
}

private struct ReplayGatedSecureInstall: SecureInstallChecking {
    let gate: ReplaySecureGate
    func status() async -> SecureInstallReport {
        await gate.pass(); return VerifiedSecureInstall().status()
    }

    func perform() async -> SecureInstallReport {
        VerifiedSecureInstall().perform()
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct MonitorActionReplayTests {
    @Test
    func `an in flight logout retry cannot tear down after a newer owner login`() async throws {
        let flag = ReplayFailureFlag(), gate = ReplaySecureGate()
        let h = try ControllerHarness(
            secureInstall: ReplayGatedSecureInstall(gate: gate),
            journalTransform: { ReplayFailOnceJournal(base: $0, flag: flag) },
        )
        try await h.install(); _ = try await h.start()
        let login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        flag.arm(); login.send(consoleUID: nil)
        try await waitForCondition { await monitoring.pendingLifecycleRetries == 1 }
        #expect(!h.trace.calls.contains("engine.shutdown"))
        await gate.arm(); h.clock.advance(.seconds(5))
        let retry = Task { await monitoring.retryPending() }
        try await waitForCondition { await gate.blocked }
        login.send(consoleUID: 501)
        try await waitForCondition { await monitoring.actionRevision == 2 }
        #expect(!h.trace.calls.contains("engine.shutdown"))
        await gate.release(); await retry.value
        #expect(!h.trace.calls.contains("engine.shutdown"), "an in flight stale logout retry tore down after owner login")
        #expect(h.journal.snapshot().loginSuspended != true)
        #expect(await h.controller.status.protection == .protected)
        await monitoring.stop()
    }

    @Test
    func `a failed logout is not replayed after the owner logs back in`() async throws {
        let flag = ReplayFailureFlag()
        let h = try ControllerHarness(journalTransform: { ReplayFailOnceJournal(base: $0, flag: flag) })
        try await h.install(); _ = try await h.start()
        try await h.controller.consoleUserChanged(501)
        let login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        flag.arm()
        login.send(consoleUID: nil)
        for _ in 0 ..< 20000 where flag.armed {
            await Task.yield()
        }
        for _ in 0 ..< 5000 {
            await Task.yield()
        }
        #expect(!h.trace.calls.contains("engine.shutdown"))
        login.send(consoleUID: 501)
        for _ in 0 ..< 5000 {
            await Task.yield()
        }
        #expect(!h.trace.calls.contains("engine.shutdown"))
        h.clock.advance(.seconds(61)); await monitoring.retryPending()
        for _ in 0 ..< 5000 {
            await Task.yield()
        }
        let afterRetry = h.trace.calls.contains("engine.shutdown")
        #expect(h.journal.snapshot().loginSuspended != true)
        #expect(h.journal.snapshot().intent != nil)
        #expect(!afterRetry, "stale logout replayed after the owner logged back in")
        await monitoring.stop()
    }

    @Test
    func `a failed logout retries after five seconds without losing the console transition`() async throws {
        let flag = ReplayFailureFlag()
        let h = try ControllerHarness(journalTransform: { ReplayFailOnceJournal(base: $0, flag: flag) })
        try await h.install(); _ = try await h.start()
        let login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        await h.controller.postponeMaintenanceRetry()
        flag.arm(); login.send(consoleUID: nil)
        for _ in 0 ..< 20000 where flag.armed {
            await Task.yield()
        }
        for _ in 0 ..< 5000 {
            await Task.yield()
        }
        #expect(!h.trace.calls.contains("engine.shutdown"))
        h.clock.advance(.seconds(5)); await monitoring.retryPending()
        #expect(h.journal.snapshot().loginSuspended == true)
        #expect(h.trace.calls.contains("engine.shutdown"))
        await monitoring.stop()
    }

    @Test(arguments: [false, true])
    func `failed wake retries after five seconds unless a newer sleep supersedes it`(superseded: Bool) async throws {
        let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
        let power = FakePowerMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: power, login: FakeLoginSessionMonitor(), ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        await h.controller.postponeMaintenanceRetry()
        h.trace.fail(at: "engine.bump"); power.send(.wake)
        for _ in 0 ..< 20000 where !h.trace.calls.contains("engine.bump") {
            await Task.yield()
        }
        for _ in 0 ..< 5000 {
            await Task.yield()
        }
        if superseded {
            power.send(.sleep)
            for _ in 0 ..< 5000 {
                await Task.yield()
            }
        }
        h.clock.advance(.seconds(5)); await monitoring.retryPending()
        #expect(h.trace.calls.filter { $0 == "engine.bump" }.count == (superseded ? 1 : 2))
        await monitoring.stop()
    }
}

private extension TunnelController {
    func postponeMaintenanceRetry() {
        maintenanceState.retryAttempt = 3; maintenanceState.retryAt = clock.now + .seconds(60)
    }
}
