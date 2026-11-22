// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore

/// The first status publication of a daemon run (DEC-011). From `arm` until startup has attempted to restore the journal
/// policy, nothing is published and nothing that can change state is served: a status read waits at most `statusHold` and
/// then answers `recovering`, and any other request waits within its client budget. `open` records the first publication
/// (sequence 1, measured as the restore attempt ended) before it admits anything else. Every status read, including one that
/// waited for the opening, measures its own current sample after it. The fence keeps that publication unchanged for the
/// run, and every telemetry reply carries it as `startup` (DEC-018). A fence that is never armed (a composition that is
/// never run) holds nothing.
package final class StartupFence: Sendable {
    /// A status read waits this long for the restore, inside the client's 5 s status budget.
    package static let statusHold: Duration = .seconds(3)

    private enum Phase { case idle, restoring, capturing, open }

    private struct State {
        var phase = Phase.idle
        var first: StatusMeasurement?
        var waiters: [UUID: CheckedContinuation<Bool, Never>] = [:]
        /// Deadlines that passed before their waiter registered.
        var expired: Set<UUID> = []
    }

    private let state = Mutex(State())

    package init() {}

    /// Closes the fence for this run, before the listener starts.
    package func arm() {
        state.withLock { state in
            if state.phase == .idle {
                state.phase = .restoring
            }
        }
    }

    /// Requests waiting for the opening.
    package var waiting: Int {
        state.withLock { $0.waiters.count }
    }

    /// Whether a request passes without waiting.
    package var isOpen: Bool {
        state.withLock { $0.phase == .idle || $0.phase == .open }
    }

    /// Claims the capture of the first publication: true once per run, for whichever startup step ends the restore first.
    package func beginCapture() -> Bool {
        state.withLock { state in
            guard state.phase == .restoring else { return false }
            state.phase = .capturing
            return true
        }
    }

    /// Records the first publication, then admits every waiting request.
    package func open(first: StatusMeasurement?) {
        let waiters = state.withLock { state -> [CheckedContinuation<Bool, Never>] in
            guard state.phase != .open else { return [] }
            state.phase = .open
            state.first = first
            state.expired = []
            defer { state.waiters = [:] }
            return Array(state.waiters.values)
        }
        for waiter in waiters {
            waiter.resume(returning: true)
        }
    }

    /// The run's first publication, kept for the run once the fence opened (DEC-018); nil before then.
    package var first: StatusMeasurement? {
        state.withLock { $0.phase == .open ? $0.first : nil }
    }

    /// Waits until the fence opens or `bound` passes on `clock`; true when it opened.
    package func wait(bound: Duration, clock: XPCClock) async -> Bool {
        let id = UUID()
        let deadline = Task { [weak self] in
            do { try await clock.sleep(bound) } catch { return }
            self?.expire(id)
        }
        defer { deadline.cancel() }
        return await withCheckedContinuation { continuation in
            let outcome = state.withLock { state -> Bool? in
                if state.phase == .idle || state.phase == .open {
                    return true
                }
                if state.expired.remove(id) != nil {
                    return false
                }
                state.waiters[id] = continuation
                return nil
            }
            if let outcome {
                continuation.resume(returning: outcome)
            }
        }
    }

    private func expire(_ id: UUID) {
        let waiter = state.withLock { state -> CheckedContinuation<Bool, Never>? in
            if let waiter = state.waiters.removeValue(forKey: id) {
                return waiter
            }
            if state.phase == .restoring || state.phase == .capturing {
                state.expired.insert(id)
            }
            return nil
        }
        waiter?.resume(returning: false)
    }
}
