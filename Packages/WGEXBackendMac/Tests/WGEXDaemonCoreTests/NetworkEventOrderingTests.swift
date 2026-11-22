// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting

@Suite(.timeLimit(.minutes(1)))
private struct NetworkEventOrderingTests {
    @Test
    func `route and configd monitors firing in the same tick produce one ordered transaction`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let routes = FakeRouteMonitor(), underlay = FakeUnderlayMonitor()
        let next = UnderlaySnapshot(v4: 14, v6: nil, resolvers: ["192.0.2.54"], interfaceNames: ["underlay-test"])
        let reads = HostTrace()
        let monitors = DaemonNetworkMonitoring(
            controller: harness.controller, routes: routes, underlay: underlay,
            power: FakePowerMonitor(), login: FakeLoginSessionMonitor(), ownPID: 77, clock: harness.clock,
            readUnderlay: { try reads.record("read"); return UnderlayEvent(snapshot: next, satisfied: true) },
        )
        try await monitors.start()
        let before = harness.trace.calls.filter { $0 == "engine.bump" }.count
        routes.send(.init(type: 3, index: 4, pid: 9))
        underlay.send(.init(snapshot: next, satisfied: true))
        // Let both injected streams deliver while the shared fake time remains unchanged.
        for _ in 0 ..< 1000 {
            await Task.yield()
        }
        try await waitForCondition { harness.clock.pendingSleeps.contains(.milliseconds(500)) }
        harness.clock.advance(.milliseconds(500))
        try await waitForCondition {
            let applied = await harness.controller.underlay
            let reconciling = await monitors.reconciliationInFlight
            return applied == next && !reconciling
        }
        #expect(reads.calls == ["read"])
        #expect(harness.trace.calls.filter { $0 == "engine.bump" }.count == before + 1)
        #expect(await harness.controller.status.protection == .blocked)
        await monitors.stop()
    }
}
