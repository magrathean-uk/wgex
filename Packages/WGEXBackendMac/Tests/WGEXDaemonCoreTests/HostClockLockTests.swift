// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
@testable import WGEXDaemonCore

/// M1-30 NF2: the fake `HostClock` resumed its sleepers while holding its lock, and its cancellation handler took the same
/// lock. Cancelling a task runs its cancellation handlers while the canceller holds the task's status-record lock;
/// resuming a continuation needs that same status-record lock. A cancel and an `advance` that fall due together (an
/// operation finishing on the tick of its own deadline) therefore block each other for good, which no Swift Testing time
/// limit can break (the shape that hung VERIFY's random-spin R1 loop once in about 2,400 runs).
private struct RoundState {
    var armed = 0, operations = 0, sleepers = 0, completed = 0
    var sleeper: Task<Void, Never>?
}

private final class Round: Sendable {
    let state = Mutex(RoundState())
    func read<T>(_ body: (RoundState) -> T) -> T {
        state.withLock { body($0) }
    }
}

/// The wait fails only when no round completes for `stallLimit`: a deadlock stops progress for good, while a heavily
/// loaded host (M04-rc8 saw a 1-minute load of 134) only slows the rounds down. The suite limit is the outer backstop.
@Suite(.timeLimit(.minutes(10)))
private struct HostClockLockTests {
    @Test
    func `advancing the manual clock while a due sleeper is cancelled never deadlocks`() async {
        let clock = HostClock(), round = Round(), rounds = 3000
        // Plain threads for all three actors: a lock inversion then blocks the threads that cause it, never the pool.
        let canceller = Thread {
            for index in 1 ... rounds {
                while round.read({ $0.armed }) < index {
                    sched_yield()
                }
                round.state.withLock { $0.sleeper }?.cancel()
                round.state.withLock { $0.operations += 1 }
            }
        }
        let advancer = Thread {
            for index in 1 ... rounds {
                while round.read({ $0.armed }) < index {
                    sched_yield()
                }
                clock.advance(.seconds(1))
                round.state.withLock { $0.operations += 1 }
            }
        }
        let coordinator = Thread {
            for index in 1 ... rounds {
                let sleeper = Task {
                    try? await clock.sleep(for: .seconds(1))
                    round.state.withLock { $0.sleepers += 1 }
                }
                round.state.withLock { $0.sleeper = sleeper }
                while clock.pendingSleeps.isEmpty {
                    sched_yield()
                }
                round.state.withLock { $0.armed = index }
                while round.read({ $0.operations }) < 2 * index {
                    sched_yield()
                }
                while round.read({ $0.sleepers }) < index {
                    sched_yield()
                }
                round.state.withLock { $0.completed = index }
            }
        }
        canceller.start(); advancer.start(); coordinator.start()
        let finished = await progressing(round, until: rounds, stallLimit: .seconds(30))
        #expect(finished, "the manual clock deadlocked after \(round.read { $0.completed }) of \(rounds) rounds")
    }

    /// True once every round completed; false as soon as `stallLimit` passes with no newly completed round.
    private func progressing(_ round: Round, until rounds: Int, stallLimit: Duration) async -> Bool {
        var seen = -1, lastProgress = ContinuousClock.now
        while true {
            let completed = round.read { $0.completed }
            if completed == rounds {
                return true
            }
            if completed != seen {
                seen = completed; lastProgress = .now
            } else if lastProgress.duration(to: .now) >= stallLimit {
                return false
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
    }
}
