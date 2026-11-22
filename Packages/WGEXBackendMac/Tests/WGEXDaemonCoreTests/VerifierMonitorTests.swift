// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting

private actor FailingMonitorRead {
    private(set) var count = 0
    func read() throws -> UnderlayEvent {
        count += 1
        if count < 3 {
            throw HostTestError.injected
        }
        return .init(snapshot: ControllerHarness.underlay, satisfied: true)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct VerifierMonitorTests {
    @Test
    func `a successful power action is not replayed when the subsequent read retries`() async throws {
        let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
        let power = FakePowerMonitor(), route = FakeRouteMonitor(), reader = FailingMonitorRead()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: route, underlay: FakeUnderlayMonitor(),
            power: power, login: FakeLoginSessionMonitor(), ownPID: 123, clock: h.clock,
            readUnderlay: { try await reader.read() },
        )
        try await monitoring.start()
        power.send(.wake); route.send(.init(type: 3, index: 4, pid: 456))
        await debounce(h.clock)
        for _ in 0 ..< 10000 where await reader.count == 0 {
            await Task.yield()
        }
        let before = h.trace.calls.filter { $0 == "engine.bump" }.count
        #expect(before == 1)
        h.clock.advance(.seconds(5)); await monitoring.retryPending()
        #expect(h.trace.calls.filter { $0 == "engine.bump" }.count == before)
        h.clock.advance(.seconds(15)); await monitoring.retryPending()
        #expect(await reader.count == 3)
        route.send(.init(type: 3, index: 4, pid: 456))
        for _ in 0 ..< 10000 {
            await Task.yield()
        }
        #expect(await reader.count == 3)
        h.clock.advance(.milliseconds(500))
        for _ in 0 ..< 10000 where await reader.count == 3 {
            await Task.yield()
        }
        #expect(await reader.count == 4)
        await monitoring.stop()
    }

    @Test(arguments: [false, true])
    func `power and login actions bypass an existing maintenance backoff`(loginEvent: Bool) async throws {
        let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
        try await h.controller.consoleUserChanged(501)
        h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { try await h.controller.tick() }
        let power = FakePowerMonitor(), login = FakeLoginSessionMonitor()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(),
            power: power, login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { .init(snapshot: ControllerHarness.underlay, satisfied: true) },
        )
        try await monitoring.start()
        let before = h.trace.calls.count
        if loginEvent {
            login.send(consoleUID: nil)
        } else {
            power.send(.wake)
        }
        try await waitForCondition {
            if loginEvent {
                return h.journal.snapshot().loginSuspended == true && h.trace.calls.contains("engine.shutdown")
            }
            return h.trace.calls.dropFirst(before).contains("engine.bump")
                && h.trace.calls.dropFirst(before).contains("engine.handshake")
        }
        #expect(h.clock.now == .zero)
        await monitoring.stop()
    }

    @Test
    func `logout bypasses a monitor read retry without advancing fake time`() async throws {
        let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
        let route = FakeRouteMonitor(), login = FakeLoginSessionMonitor(), reader = FailingMonitorRead()
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: route, underlay: FakeUnderlayMonitor(),
            power: FakePowerMonitor(), login: login, ownPID: 123, clock: h.clock,
            readUnderlay: { try await reader.read() },
        )
        try await monitoring.start()
        route.send(.init(type: 3, index: 4, pid: 456))
        await debounce(h.clock)
        try await waitForCondition { await reader.count == 1 }
        let receivedAt = h.clock.now
        login.send(consoleUID: nil)
        try await waitForCondition { h.journal.snapshot().loginSuspended == true && h.trace.calls.contains("engine.shutdown") }
        #expect(h.clock.now == receivedAt)
        #expect(h.trace.calls.contains("engine.shutdown"))
        await monitoring.stop()
    }

    @Test
    func `the explicit owned DNS key is ignored without suppressing other service UUIDs`() {
        let owned = DNSConfigurator.key(profileID: UUID())
        let primary = DNSConfigurator.key(profileID: UUID())
        #expect(!SystemConfigurationNotifications.isRelevant(owned, ignoring: [owned]))
        #expect(SystemConfigurationNotifications.isRelevant(primary, ignoring: [owned]))
        #expect(!SystemConfigurationNotifications.isRelevant("State:/Network/Interface/utun7/IPv4", ignoring: []))
    }

    private func debounce(_ clock: HostClock) async {
        for _ in 0 ..< 10000 where !clock.pendingSleeps.contains(.milliseconds(500)) {
            await Task.yield()
        }
        clock.advance(.milliseconds(500))
        for _ in 0 ..< 10000 {
            await Task.yield()
        }
    }
}
