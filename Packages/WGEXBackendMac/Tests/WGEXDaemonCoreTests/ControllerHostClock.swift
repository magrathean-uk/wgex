// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
@testable import WGEXDaemonCore

package final class HostClock: DaemonClock {
    private struct Waiter: Sendable { let at: Duration; let continuation: CheckedContinuation<Void, any Error> }
    private struct State: Sendable { var now: Duration = .zero; var waiters: [UUID: Waiter] = [:] }
    private let state = Mutex(State())
    package let sleeps: AsyncStream<Duration>
    private let sink: AsyncStream<Duration>.Continuation
    package init() {
        (sleeps, sink) = AsyncStream.makeStream()
    }

    package var now: Duration {
        state.withLock { $0.now }
    }

    package var wallNow: Date {
        Date(timeIntervalSince1970: 1_700_000_000 + Double(now.components.seconds))
    }

    /// No continuation is resumed, and nothing is yielded, while the lock is held: cancelling a task runs its cancellation
    /// handler under the task's status-record lock, and resuming a continuation needs that same lock, so a resume under
    /// this lock deadlocks against a cancel that wants this lock (M1-30 NF2, as `DaemonEventChannel` in M1-29 R3).
    package func sleep(for duration: Duration) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let registered = state.withLock { value -> Bool in
                    guard !Task.isCancelled else { return false }
                    value.waiters[id] = Waiter(at: value.now + duration, continuation: continuation)
                    return true
                }
                if registered {
                    sink.yield(duration)
                } else {
                    continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            let waiter = self.state.withLock { $0.waiters.removeValue(forKey: id) }
            waiter?.continuation.resume(throwing: CancellationError())
        }
    }

    package var pendingSleeps: [Duration] {
        state.withLock { value in value.waiters.values.map { $0.at - value.now } }
    }

    package func advance(_ duration: Duration) {
        let ready = state.withLock { value -> [Waiter] in
            value.now += duration
            let due = value.waiters.filter { $0.value.at <= value.now }
            for id in due.keys {
                value.waiters.removeValue(forKey: id)
            }
            return Array(due.values)
        }
        for waiter in ready {
            waiter.continuation.resume()
        }
    }
}
