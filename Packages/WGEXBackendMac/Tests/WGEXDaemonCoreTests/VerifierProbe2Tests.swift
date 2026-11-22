// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXEngineInterface

private actor LostUnderlay {
    static let restored = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["restored0"])
    var lost = true
    func restore() {
        lost = false
    }

    func read() -> UnderlayEvent {
        lost ? .init(snapshot: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []), satisfied: false)
            : .init(snapshot: Self.restored, satisfied: true)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct VerifierProbe2Tests {
    @Test
    func `probe interface loss through the merged monitor is not a monitor failure`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let underlay = FakeUnderlayMonitor(), reader = LostUnderlay()
        let monitoring = DaemonNetworkMonitoring(
            controller: harness.controller, routes: FakeRouteMonitor(), underlay: underlay,
            power: FakePowerMonitor(), login: FakeLoginSessionMonitor(), ownPID: 123, clock: harness.clock,
            readUnderlay: { await reader.read() },
        )
        try await monitoring.start()
        await harness.controller.consume(
            .handshakeCompleted(peer: harness.profile.peers[0].publicKey, at: harness.clock.wallNow),
            generation: harness.controller.currentGeneration,
        )
        underlay.send(.init(snapshot: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []), satisfied: false))
        try await waitForCondition { harness.clock.pendingSleeps.contains(.milliseconds(500)) }
        harness.clock.advance(.milliseconds(500))
        try await waitForCondition {
            let state = await harness.controller.recoveryObservation()
            let networkIdle = await !monitoring.reconciliationInFlight
            return networkIdle && state.retryAt != nil && !state.inFlight
        }
        #expect(await harness.controller.protectionFailureReason == nil)
        try await saturateRecovery(harness, monitoring: monitoring)
        await reader.restore()
        let restoredAt = harness.clock.now
        underlay.send(.init(snapshot: LostUnderlay.restored, satisfied: true))
        try await waitForCondition { harness.clock.pendingSleeps.contains(.milliseconds(500)) }
        harness.clock.advance(.milliseconds(500))
        try await waitForCondition {
            let state = await harness.controller.recoveryObservation()
            let networkIdle = await !monitoring.reconciliationInFlight
            return networkIdle && !state.inFlight && state.underlay == LostUnderlay.restored
                && (state.active || state.retryAt.map { $0 <= harness.clock.now + .seconds(5) } == true)
        }
        let state = await harness.controller.recoveryObservation()
        if !state.active {
            let due = try #require(state.retryAt)
            harness.clock.advance(max(.zero, due - harness.clock.now))
            try await harness.controller.tick(); await monitoring.retryPending()
        }
        try await waitForCondition {
            let state = await harness.controller.recoveryObservation()
            return state.active && !state.inFlight && state.status.protection == .protected
        }
        let recoveredAt = harness.clock.now
        #expect(recoveredAt - restoredAt <= .milliseconds(6500))
        await monitoring.stop()
    }

    private func saturateRecovery(_ harness: ControllerHarness, monitoring: DaemonNetworkMonitoring) async throws {
        for delay in [5, 15, 60] {
            harness.clock.advance(.seconds(delay))
            await monitoring.retryPending(); try? await harness.controller.tick()
            try await waitForCondition {
                let state = await harness.controller.recoveryObservation()
                let networkIdle = await !monitoring.reconciliationInFlight
                return networkIdle && !state.inFlight
            }
        }
        let deadline = try #require(await harness.controller.maintenanceState.retryAt)
        #expect(deadline - harness.clock.now == .seconds(60))
    }
}
