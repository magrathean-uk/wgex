// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonCore

/// Explicitly driven route notifications with no PF_ROUTE socket.
public struct FakeRouteMonitor: RouteMonitoring {
    private let pair = AsyncStream<RouteNotification>.makeStream()
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Returns the injected event stream without starting a system monitor.
    public func start() -> AsyncStream<RouteNotification> {
        pair.stream
    }

    /// Delivers fixture input through the injected port.
    public func send(_ event: RouteNotification) {
        pair.continuation.yield(event)
    }

    /// Finishes this fixture event stream.
    public func stop() {
        pair.continuation.finish()
    }
}
