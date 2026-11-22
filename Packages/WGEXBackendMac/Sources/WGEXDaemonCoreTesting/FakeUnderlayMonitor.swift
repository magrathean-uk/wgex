// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonCore

/// Explicitly driven underlay observations with no configd subscription.
public struct FakeUnderlayMonitor: UnderlayMonitoring {
    private let pair = AsyncStream<UnderlayEvent>.makeStream(bufferingPolicy: .bufferingNewest(32))
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Returns the injected event stream without starting a system monitor.
    public func start() -> AsyncStream<UnderlayEvent> {
        pair.stream
    }

    /// Delivers fixture input through the injected port.
    public func send(_ event: UnderlayEvent) {
        pair.continuation.yield(event)
    }

    /// Finishes this fixture event stream.
    public func stop() {
        pair.continuation.finish()
    }
}
