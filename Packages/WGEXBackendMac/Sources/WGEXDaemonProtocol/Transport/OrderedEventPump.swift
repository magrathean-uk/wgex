// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// One bounded FIFO and one consumer per connection. Overflow delivers an explicit loss marker.
package final class OrderedEventPump: Sendable {
    private struct State {
        var lost = false
        var closed = false
    }

    private final class PumpState: Sendable { let value = Mutex(State()) }
    private let state: PumpState
    private let continuation: AsyncStream<Data>.Continuation
    private let task: Task<Void, Never>

    package init(deliver: @escaping @Sendable (Data) async -> Void) {
        let state = PumpState()
        self.state = state
        let pair = AsyncStream<Data>.makeStream(bufferingPolicy: .bufferingNewest(32))
        continuation = pair.continuation
        task = Task {
            for await bytes in pair.stream {
                guard !Task.isCancelled else { return }
                if (try? WireCodec.decode(Event.self, from: bytes)) == .subscriptionLost {
                    state.value.withLock { $0.lost = false }
                }
                await deliver(bytes)
            }
        }
    }

    /// Returns false once delivery has overflowed; the subscription must be renewed.
    @discardableResult
    package func enqueue(_ bytes: Data) -> Bool {
        state.value.withLock { state in
            guard !state.closed, !state.lost else { return false }
            if case .dropped = continuation.yield(bytes) {
                state.lost = true
                if let marker = try? WireCodec.encode(Event.subscriptionLost) {
                    continuation.yield(marker)
                }
                return false
            }
            return true
        }
    }

    package func close() {
        state.value.withLock { $0.closed = true }
        continuation.finish()
        task.cancel()
    }

    deinit { continuation.finish(); task.cancel() }
}
