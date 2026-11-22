// SPDX-License-Identifier: MIT
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol

public extension TunnelController {
    /// Host observations use the ordinary service event channel; no separate controller status subscription exists.
    func statusUpdates() -> AsyncStream<TunnelStatus> {
        let events = wireEvents.observe()
        let pair = AsyncStream<TunnelStatus>.makeStream(bufferingPolicy: .bufferingNewest(32))
        pair.continuation.yield(status)
        let task = Task {
            for await item in events {
                if case let .status(status) = item.event {
                    pair.continuation.yield(status)
                }
            }
            pair.continuation.finish()
        }
        pair.continuation.onTermination = { _ in task.cancel() }
        return pair.stream
    }
}
