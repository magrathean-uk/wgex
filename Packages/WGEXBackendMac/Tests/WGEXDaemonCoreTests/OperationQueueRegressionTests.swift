// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct OperationQueueRegressionTests {
    @Test
    func `captive timer close waits for maintenance instead of being dropped`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .verify)
        try await harness.install(); _ = try await harness.start()
        try await harness.controller.openCaptiveWindow(seconds: 10, connectionUID: 501)
        try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(10)) }
        let timer = try #require(await harness.controller.captiveTask)
        let maintenance = Task {
            try await harness.controller.maintenance { _, epoch in try await gate.before(.verify, generation: epoch) }
        }
        await gate.wait()
        harness.clock.advance(.seconds(10))
        for _ in 0 ..< 1000 {
            await Task.yield()
        }
        #expect(harness.journal.snapshot().captiveWindow != nil)
        await gate.release(); try await maintenance.value; await timer.value
        #expect(harness.journal.snapshot().captiveWindow == nil)
        #expect(await harness.controller.status.phase == .active(harness.journal.snapshot().generation))
    }

    @Test(arguments: [false, true])
    func `start during removal waits then reports the resulting registration`(anotherProfile: Bool) async throws {
        let gate = StepGate(point: .removeDNS), harness = try ControllerHarness(gate: gate)
        try await harness.install(); _ = try await harness.start()
        let other = try ControllerHarness.makeProfile()
        if anotherProfile {
            _ = try await harness.registry.installProfile(other, expectedRevision: nil, connectionUID: 501)
            try await harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        }
        let fixture = CompositionFixture(harness: harness); try await fixture.connect()
        let removal = Task { try await fixture.call(.removeProfile(harness.profile.id, purgeSecrets: false)) }
        await gate.wait()
        let requested = anotherProfile ? other.id : harness.profile.id
        let start = Task { try await fixture.call(.startIntent(profileID: requested, transport: nil, hasSecrets: false)) }
        for _ in 0 ..< 1000 {
            await Task.yield()
        }
        await gate.release()
        #expect(try await removal.value == .ok)
        let reply = try await start.value
        if anotherProfile {
            guard case .started = reply else { Issue.record("Queued start did not succeed"); return }
            #expect(await harness.controller.activeProfileID() == other.id)
        } else {
            #expect(reply == .error(.profileNotFound(requested)))
            #expect(DaemonError.profileNotFound(requested).presentation.cliExitCode == 11)
        }
    }
}
