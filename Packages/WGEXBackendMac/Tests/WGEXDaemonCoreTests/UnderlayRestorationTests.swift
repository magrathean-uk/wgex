// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXPolicy

private actor RestorationRead {
    var value: UnderlayEvent
    var fail = false
    private(set) var reads = 0
    init(_ snapshot: UnderlaySnapshot) {
        value = .init(snapshot: snapshot, satisfied: true)
    }

    func update(_ snapshot: UnderlaySnapshot, fail: Bool = false) {
        value = .init(snapshot: snapshot, satisfied: true); self.fail = fail
    }

    func read() throws -> UnderlayEvent {
        reads += 1
        if fail {
            fail = false; throw HostTestError.injected
        }
        return value
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct UnderlayRestorationTests {
    @Test
    func `IPv6 return still bypasses backoff after a canary failure while waiting`() async throws {
        let initial = UnderlaySnapshot(
            v4: 4,
            v6: 6,
            resolvers: ["192.0.2.53"],
            interfaceNames: ["en-test"],
            ipv6DefaultRouteAvailable: false,
        )
        let h = try await prepareIPv6Recovery(initial: initial, existingGeneration: false)
        await h.controller.setPolicyFailure(DaemonFailure(code: .pfCanaryFailed))
        #expect(await h.controller.status.protectionNote == .ipv6Unavailable)
        await h.controller.clearPolicyFailure()
        #expect(await h.controller.status.protectionNote == .ipv6Unavailable)
        let returned = UnderlayEvent(snapshot: .init(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["en-test"], ipv6DefaultRouteAvailable: true,
        ), satisfied: true)
        #expect(await h.controller.restoresUnderlay(returned))
        let returnedAt = h.clock.now
        try await h.controller.networkChanged(trigger: .configuration, underlay: returned)
        if await h.controller.status.protection != .protected {
            let due = try #require(await h.controller.maintenanceState.retryAt)
            #expect(due <= h.clock.now + .seconds(5))
            h.clock.advance(max(.zero, due - h.clock.now)); try await h.controller.tick()
        }
        #expect(await h.controller.status.protection == .protected)
        #expect(h.clock.now - returnedAt <= .seconds(5))
        await h.controller.cancelBackgroundWork()
    }

    @Test
    func `usable identity flapping preserves the saturated failed server backoff`() async throws {
        let h = try ControllerHarness(); try await h.install(); await h.ports.setAnswers([])
        await #expect(throws: (any Error).self) { _ = try await h.start() }
        for delay in [5, 15] {
            h.clock.advance(.seconds(delay))
            await #expect(throws: (any Error).self) { try await h.controller.tick() }
        }
        let deadline = try #require(await h.controller.maintenanceState.retryAt)
        #expect(deadline - h.clock.now == .seconds(60))
        let underlay = FakeUnderlayMonitor(), reader = RestorationRead(ControllerHarness.underlay)
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: underlay,
            power: FakePowerMonitor(), login: FakeLoginSessionMonitor(), ownPID: 123, clock: h.clock,
            readUnderlay: { try await reader.read() },
        )
        try await monitoring.start()
        let starts = h.trace.calls.filter { $0 == "resolver.resolve" }.count
        for index in 0 ..< 4 {
            let value = UnderlaySnapshot(
                v4: index.isMultiple(of: 2) ? 8 : 4, v6: index.isMultiple(of: 2) ? nil : 6,
                resolvers: ["192.0.2.53"], interfaceNames: ["usable-\(index)"], ipv6DefaultRouteAvailable: !index.isMultiple(of: 2),
            )
            await reader.update(value); underlay.send(.init(snapshot: value, satisfied: true))
            try await waitForCondition { h.clock.pendingSleeps.contains(.milliseconds(500)) }
            h.clock.advance(.milliseconds(500))
            try await waitForCondition { await h.controller.underlay == value }
            try await waitForCondition { await h.controller.operation == nil }
            #expect(await h.controller.maintenanceState.retryAt == deadline)
            #expect(await h.controller.maintenanceState.retryAttempt == 3)
        }
        #expect(h.trace.calls.filter { $0 == "resolver.resolve" }.count == starts)
        await monitoring.stop()
    }

    @Test(arguments: [false, true])
    func `IPv6 default restoration bypasses monitor and controller saturated waits`(existingGeneration: Bool) async throws {
        let initial = UnderlaySnapshot(
            v4: 4,
            v6: 6,
            resolvers: ["192.0.2.53"],
            interfaceNames: ["en-test"],
            ipv6DefaultRouteAvailable: false,
        )
        let h = try await prepareIPv6Recovery(initial: initial, existingGeneration: existingGeneration)
        let underlay = FakeUnderlayMonitor(), reader = RestorationRead(initial)
        await reader.update(initial, fail: true)
        let monitoring = DaemonNetworkMonitoring(
            controller: h.controller, routes: FakeRouteMonitor(), underlay: underlay,
            power: FakePowerMonitor(), login: FakeLoginSessionMonitor(), ownPID: 123, clock: h.clock,
            readUnderlay: { try await reader.read() },
        )
        try await monitoring.start(); underlay.send(.init(snapshot: initial, satisfied: true))
        try await waitForCondition { h.clock.pendingSleeps.contains(.milliseconds(500)) }
        h.clock.advance(.milliseconds(500))
        try await waitForCondition {
            let state = await h.controller.recoveryObservation()
            let networkIdle = await !monitoring.reconciliationInFlight
            return networkIdle && !state.inFlight && state.status.protection == .unknown
        }
        let restored = UnderlaySnapshot(
            v4: 4,
            v6: 6,
            resolvers: ["192.0.2.53"],
            interfaceNames: ["en-test"],
            ipv6DefaultRouteAvailable: true,
        )
        let restoredAt = h.clock.now
        await reader.update(restored); underlay.send(.init(snapshot: restored, satisfied: true))
        try await waitForCondition { h.clock.pendingSleeps.contains(.milliseconds(500)) }
        h.clock.advance(.milliseconds(500))
        try await waitForCondition {
            let state = await h.controller.recoveryObservation()
            let networkIdle = await !monitoring.reconciliationInFlight
            return networkIdle && !state.inFlight && state.underlay.ipv6DefaultRouteAvailable
                && (state.active || state.retryAt.map { $0 <= h.clock.now + .seconds(5) } == true)
        }
        let state = await h.controller.recoveryObservation()
        if !state.active {
            let due = try #require(state.retryAt)
            h.clock.advance(max(.zero, due - h.clock.now)); try await h.controller.tick()
        }
        #expect(await h.controller.status.protection == .protected)
        #expect(h.clock.now - restoredAt <= .seconds(5))
        await monitoring.stop()
    }

    private func prepareIPv6Recovery(initial: UnderlaySnapshot, existingGeneration: Bool) async throws -> ControllerHarness {
        let routed = UnderlaySnapshot(v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["en-test"], ipv6DefaultRouteAvailable: true)
        let h = try ControllerHarness(underlay: existingGeneration ? routed : initial)
        var profile = h.profile
        profile.peers[0].endpoint = try Endpoint(validatingHost: "2001:db8::1", port: 51820)
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        if existingGeneration {
            _ = try await h.start()
            await #expect(throws: (any Error).self) {
                try await h.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: initial, satisfied: true))
            }
            await h.controller.saturateIPv6Recovery()
        } else {
            await #expect(throws: (any Error).self) { _ = try await h.start() }
            for delay in [5, 15] {
                h.clock.advance(.seconds(delay))
                await #expect(throws: (any Error).self) { try await h.controller.tick() }
            }
        }
        #expect(await h.controller.maintenanceState.retryAt == h.clock.now + .seconds(60))
        return h
    }
}

private extension TunnelController {
    func saturateIPv6Recovery() {
        maintenanceState.retryAttempt = 3; maintenanceState.retryAt = clock.now + .seconds(60)
    }
}
