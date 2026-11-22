// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXDaemonProtocol

/// FIFO admission across actor reentrancy. A waiter cancelled while queued is removed and refused; a caller that is
/// already cancelled on entry is admitted or queued like any other, because rollback runs inside the cancelled
/// predecessor task (`TunnelController.undo`) and must never be refused a port. An admitted transaction is never
/// interrupted.
package final class SerialOperationSlot: Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct State {
        var occupied = false
        var waiters: [Waiter] = []
    }

    private let state = Mutex(State())

    package func acquire() async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let admitted = state.withLock { state in
                    if state.occupied {
                        state.waiters.append(Waiter(id: id, continuation: continuation))
                        return false
                    }
                    state.occupied = true
                    return true
                }
                if admitted {
                    continuation.resume()
                }
            }
        } onCancel: {
            let cancelled = self.state.withLock { state -> Waiter? in
                guard let index = state.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return state.waiters.remove(at: index)
            }
            cancelled?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Host tests only: the number of queued waiters, so a test can open a held gate once a competitor is queued.
    package var waiterCount: Int {
        state.withLock { $0.waiters.count }
    }

    /// Typed ports preserve their canonical error contract when a queued wait is cancelled.
    package func acquirePort() async throws(DaemonFailure) {
        do { try await acquire() }
        catch { throw DaemonFailure(code: .tunnelCancelled) }
    }

    package func release() {
        let next = state.withLock { state -> Waiter? in
            guard !state.waiters.isEmpty else { state.occupied = false; return nil }
            return state.waiters.removeFirst()
        }
        next?.continuation.resume()
    }
}
