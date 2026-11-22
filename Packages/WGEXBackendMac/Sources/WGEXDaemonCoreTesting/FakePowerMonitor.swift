// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonCore

/// Explicitly driven power-event stream with no system notifications.
public struct FakePowerMonitor: PowerMonitoring {
    private let pair = AsyncStream<PowerEvent>.makeStream(bufferingPolicy: .bufferingNewest(16))
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Returns the injected event stream without starting a system monitor.
    public func start() -> AsyncStream<PowerEvent> {
        pair.stream
    }

    /// Delivers fixture input through the injected port.
    public func send(_ event: PowerEvent) {
        pair.continuation.yield(event)
    }

    /// Finishes this fixture event stream.
    public func stop() {
        pair.continuation.finish()
    }
}
