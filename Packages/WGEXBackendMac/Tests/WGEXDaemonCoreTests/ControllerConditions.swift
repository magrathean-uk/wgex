// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore

/// Leave time to record a timeout before the shortest caller suite's one-minute limit.
package func waitForCondition(timeout: Duration = .seconds(30), _ condition: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now + timeout
    while await !condition() {
        guard ContinuousClock.now < deadline else {
            Issue.record("Timed out waiting for the required test state")
            throw HostTestError.injected
        }
        try await Task.sleep(for: .milliseconds(1))
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ControllerConditionsTests {
    @Test func `condition wait tolerates delayed publication`() async throws {
        let readyAt = ContinuousClock.now + .seconds(6)
        try await waitForCondition { ContinuousClock.now >= readyAt }
    }
}

package struct ControllerRecoveryObservation: Sendable {
    package let status: TunnelStatus
    package let retryAt: Duration?
    package let inFlight: Bool
    package let underlay: UnderlaySnapshot
    package var active: Bool {
        if case .active = status.phase {
            true
        } else {
            false
        }
    }
}

package extension TunnelController {
    func recoveryObservation() -> ControllerRecoveryObservation {
        .init(status: snapshot, retryAt: maintenanceState.retryAt, inFlight: operation != nil, underlay: underlay)
    }
}
