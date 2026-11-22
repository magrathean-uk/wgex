// SPDX-License-Identifier: MIT

import Foundation
import Synchronization

/// Bridges a callback-style SDK reply to one continuation. The first outcome wins; every later outcome
/// (late reply, second callback, cancellation after delivery) is dropped, so the continuation resumes exactly once.
/// An outcome that arrives before the continuation is installed is replayed on installation.
package final class SingleResume<Value: Sendable>: Sendable {
    private struct State {
        var continuation: CheckedContinuation<Value, any Error>?
        var outcome: Result<Value, any Error>?
        var tasks: [Task<Void, Never>] = []
    }

    private let state = Mutex(State())

    package func install(_ continuation: CheckedContinuation<Value, any Error>) {
        let early = state.withLock { state -> Result<Value, any Error>? in
            if let outcome = state.outcome {
                return outcome
            }
            state.continuation = continuation
            return nil
        }
        if let early {
            continuation.resume(with: early)
        }
    }

    /// Tasks racing for the outcome; they are cancelled as soon as an outcome is accepted.
    package func attach(_ task: Task<Void, Never>) {
        let finished = state.withLock { state in
            if state.outcome != nil {
                return true
            }
            state.tasks.append(task)
            return false
        }
        if finished {
            task.cancel()
        }
    }

    /// Returns whether this outcome was the one delivered.
    @discardableResult
    package func finish(_ outcome: Result<Value, any Error>) -> Bool {
        let taken = state.withLock { state -> (CheckedContinuation<Value, any Error>?, [Task<Void, Never>])? in
            guard state.outcome == nil else { return nil }
            state.outcome = outcome
            let taken = (state.continuation, state.tasks)
            state.continuation = nil; state.tasks = []
            return taken
        }
        guard let taken else { return false }
        taken.0?.resume(with: outcome)
        for task in taken.1 {
            task.cancel()
        }
        return true
    }
}
