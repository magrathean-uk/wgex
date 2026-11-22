// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting

/// A bounded synchronous repository-read latch; it models file I/O, never a system service.
private final class ConsoleRepositoryControl: Sendable {
    private struct State { var failure = false; var hold = false; var entered = false; var released = false }
    private let state = Mutex(State())
    private let condition = NSCondition()
    var entered: Bool {
        state.withLock { $0.entered }
    }

    func arm(failing: Bool) {
        state.withLock { $0.failure = failing; $0.hold = !failing; $0.entered = false; $0.released = false }
    }

    func read() throws {
        let action = state.withLock { value -> (Bool, Bool) in
            let result = (value.failure, value.hold); value.failure = false; value.hold = false; return result
        }
        if action.0 {
            throw HostTestError.injected
        }
        guard action.1 else { return }
        condition.lock(); defer { condition.unlock() }
        state.withLock { $0.entered = true }
        let deadline = Date().addingTimeInterval(5)
        while !state.withLock({ $0.released }) {
            guard condition.wait(until: deadline) else { throw HostTestError.injected }
        }
    }

    func release() {
        condition.lock(); state.withLock { $0.released = true }; condition.broadcast(); condition.unlock()
    }
}

private struct ConsoleFaultRepository: ProfileRepository {
    let base: any ProfileRepository
    let control: ConsoleRepositoryControl
    func load(_ id: UUID) throws -> RegisteredProfile? {
        try control.read(); return try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        try base.save(profile)
    }

    func remove(_ id: UUID) throws {
        try base.remove(id)
    }

    func all() throws -> [RegisteredProfile] {
        try base.all()
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ConsoleDecisionTests {
    @Test(arguments: [false, true])
    func `a registry failure preserves the owner console for retry or a different user`(differentUser: Bool) async throws {
        let control = ConsoleRepositoryControl()
        let h = try ControllerHarness(repositoryTransform: { ConsoleFaultRepository(base: $0, control: control) })
        try await h.install(); _ = try await h.start()
        let login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start(); control.arm(failing: true); login.send(consoleUID: nil)
        try await waitForCondition { await monitoring.pendingLifecycleRetries == 1 }
        if differentUser {
            login.send(consoleUID: 502)
            try await waitForCondition { h.journal.snapshot().loginSuspended == true && h.trace.calls.contains("engine.shutdown") }
        } else {
            h.clock.advance(.seconds(5)); await monitoring.retryPending()
        }
        #expect(h.journal.snapshot().loginSuspended == true)
        #expect(h.trace.calls.contains("engine.shutdown"))
        await monitoring.stop()
    }

    @Test
    func `an operation that starts during the registry read makes logout retryable`() async throws {
        let control = ConsoleRepositoryControl()
        let h = try ControllerHarness(repositoryTransform: { ConsoleFaultRepository(base: $0, control: control) })
        try await h.install(); _ = try await h.start()
        let login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start(); control.arm(failing: false); login.send(consoleUID: nil)
        try await waitForCondition { control.entered }
        await h.controller.occupyConsoleDecisionSlot()
        control.release()
        try await waitForCondition { await monitoring.pendingLifecycleRetries == 1 }
        await h.controller.clearConsoleDecisionSlot()
        h.clock.advance(.seconds(5)); await monitoring.retryPending()
        #expect(h.journal.snapshot().loginSuspended == true)
        #expect(h.trace.calls.contains("engine.shutdown"))
        await monitoring.stop()
    }
}

private extension TunnelController {
    func occupyConsoleDecisionSlot() {
        operation = Task {}
    }

    func clearConsoleDecisionSlot() {
        operation = nil
    }
}
