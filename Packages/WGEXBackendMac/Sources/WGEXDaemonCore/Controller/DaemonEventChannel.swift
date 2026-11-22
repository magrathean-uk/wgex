// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// Bounded service events share one publication path. The primary stream retains pre-listener events.
package final class DaemonEventChannel: Sendable {
    private let primary = AsyncStream<DaemonServiceEvent>.makeStream(bufferingPolicy: .bufferingNewest(32))
    private let observers = Mutex<[UUID: AsyncStream<DaemonServiceEvent>.Continuation]>([:])

    package var stream: AsyncStream<DaemonServiceEvent> {
        primary.stream
    }

    /// The observer lock is held only to copy the subscriber list. Resuming a subscriber's consumer task takes that task's
    /// status-record lock, and dropping a subscriber cancels the task under that lock and runs `onTermination`, which takes
    /// the observer lock: yielding under it let the two threads wait on each other for good (M1-29 R3).
    package func yield(_ event: DaemonServiceEvent) {
        primary.continuation.yield(event)
        let targets = observers.withLock { Array($0.values) }
        for continuation in targets {
            continuation.yield(event)
        }
    }

    /// An additional consumer receives only events published after attachment.
    package func observe() -> AsyncStream<DaemonServiceEvent> {
        let id = UUID()
        let pair = AsyncStream<DaemonServiceEvent>.makeStream(bufferingPolicy: .bufferingNewest(32))
        observers.withLock { $0[id] = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in
            self?.observers.withLock { _ = $0.removeValue(forKey: id) }
        }
        return pair.stream
    }

    deinit {
        primary.continuation.finish()
        for continuation in observers.withLock({ Array($0.values) }) {
            continuation.finish()
        }
    }
}
