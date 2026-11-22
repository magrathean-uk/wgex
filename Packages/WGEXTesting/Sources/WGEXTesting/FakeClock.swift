// SPDX-License-Identifier: MIT

import Foundation
import Synchronization

/// A manually advanced clock. Sleepers resume only when ``advance(by:)``
/// moves `now` past their deadline, so timing tests never wait for real time.
public final class FakeClock: Clock, Sendable {
    /// A point on the fake timeline.
    public struct Instant: InstantProtocol, Hashable, Sendable {
        /// Offset from the clock's origin.
        public var offset: Swift.Duration

        /// Creates an instant.
        public init(offset: Swift.Duration) {
            self.offset = offset
        }

        /// Orders by offset.
        public static func < (lhs: Instant, rhs: Instant) -> Bool {
            lhs.offset < rhs.offset
        }

        /// The instant `duration` later.
        public func advanced(by duration: Swift.Duration) -> Instant {
            Instant(offset: offset + duration)
        }

        /// The duration from this instant to `other`.
        public func duration(to other: Instant) -> Swift.Duration {
            other.offset - offset
        }
    }

    private struct Sleeper {
        let id: UUID
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct State {
        var now: Instant
        var sleepers: [Sleeper] = []
    }

    private let state: Mutex<State>

    /// Creates a clock at `now`.
    public init(now: Instant = Instant(offset: .zero)) {
        state = Mutex(State(now: now))
    }

    /// Current fake time.
    public var now: Instant {
        state.withLock { $0.now }
    }

    /// The fake clock has no resolution limit.
    public var minimumResolution: Swift.Duration {
        .zero
    }

    /// Number of tasks currently sleeping.
    public var sleeperCount: Int {
        state.withLock { $0.sleepers.count }
    }

    /// Suspends until ``advance(by:)`` reaches `deadline`; throws on cancellation.
    public func sleep(until deadline: Instant, tolerance _: Swift.Duration? = nil) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let outcome: Result<Void, any Error>? = state.withLock { state in
                    if Task.isCancelled {
                        return .failure(CancellationError())
                    }
                    if deadline <= state.now {
                        return .success(())
                    }
                    state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    return nil
                }
                if let outcome {
                    continuation.resume(with: outcome)
                }
            }
        } onCancel: {
            let cancelled = state.withLock { state -> CheckedContinuation<Void, any Error>? in
                guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else { return nil }
                return state.sleepers.remove(at: index).continuation
            }
            cancelled?.resume(throwing: CancellationError())
        }
    }

    /// Moves time forward and resumes every sleeper whose deadline has passed.
    public func advance(by duration: Swift.Duration) {
        let due = state.withLock { state -> [CheckedContinuation<Void, any Error>] in
            state.now = state.now.advanced(by: duration)
            let now = state.now
            let ready = state.sleepers.filter { $0.deadline <= now }
            state.sleepers.removeAll { $0.deadline <= now }
            return ready.map(\.continuation)
        }
        for continuation in due {
            continuation.resume()
        }
    }

    /// Waits (by yielding) until at least `count` tasks are sleeping.
    public func waitForSleepers(_ count: Int) async {
        while sleeperCount < count {
            await Task.yield()
        }
    }
}
