// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore

/// Atomic replay and ordered AsyncStream yields under a mutex; no user callbacks execute in the critical section.
package final class StatusBroadcast: Sendable {
    private struct State {
        var current = TunnelStatus.unreported
        var observers: [UUID: AsyncStream<TunnelStatus>.Continuation] = [:]
    }

    private let state = Mutex(State())

    package func publish(_ status: TunnelStatus) {
        state.withLock { state in
            state.current = status
            for observer in state.observers.values {
                observer.yield(status)
            }
        }
    }

    package func stream() -> AsyncStream<TunnelStatus> {
        let (stream, continuation) = AsyncStream<TunnelStatus>.makeStream(bufferingPolicy: .bufferingNewest(64))
        let id = UUID()
        state.withLock { state in
            state.observers[id] = continuation
            continuation.yield(state.current)
        }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { _ = $0.observers.removeValue(forKey: id) }
        }
        return stream
    }
}
