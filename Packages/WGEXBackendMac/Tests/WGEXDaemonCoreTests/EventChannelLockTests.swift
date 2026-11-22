// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-29 R3: `DaemonEventChannel.yield` held the observer lock while it resumed the subscribers' consumer tasks. Dropping a
/// subscriber cancels its consumer task, and the cancellation runs the stream's termination handler, which takes the same
/// lock while the canceller holds the task's status-record lock; the publisher meanwhile waits for that status-record lock.
/// Both threads then block in an unfair lock for good, which no Swift Testing time limit can break.
@Suite(.timeLimit(.minutes(1)))
private struct EventChannelLockTests {
    @Test
    func `dropping a status subscriber while the controller publishes never deadlocks`() async throws {
        let harness = try ControllerHarness()
        let controller = harness.controller
        let publishing = Mutex(true), dropped = Mutex(0)
        // The publisher is the controller's own publication path (`wireEvents.yield`); the dropper is a plain thread, so a
        // lock inversion blocks the threads that cause it and nothing the cooperative pool needs.
        let publisher = Task {
            var marker: UInt64 = 0xFD00_0000
            while publishing.withLock({ $0 }) {
                marker += 1
                await controller.publishFence(marker)
                await Task.yield()
            }
        }
        let wires = controller.wireEvents
        let dropper = Thread {
            for _ in 0 ..< 2000 {
                let recorder = StatusRecorder(wires.observe())
                _ = recorder.statuses
                dropped.withLock { $0 += 1 }
            }
        }
        dropper.start()
        let finished = await eventually(within: .seconds(20)) { dropped.withLock { $0 } == 2000 }
        publishing.withLock { $0 = false }
        #expect(finished, "dropping a subscriber while publishing deadlocked after \(dropped.withLock { $0 }) subscribers")
        if finished {
            await publisher.value
        }
    }
}
