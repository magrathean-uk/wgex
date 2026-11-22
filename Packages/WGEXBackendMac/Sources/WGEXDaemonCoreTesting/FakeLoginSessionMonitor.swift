// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonCore

/// Explicitly driven console-user observations with no login-session access.
public struct FakeLoginSessionMonitor: LoginSessionMonitoring {
    private let pair = AsyncStream<UInt32?>.makeStream(bufferingPolicy: .bufferingNewest(16))
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Returns the injected event stream without starting a system monitor.
    public func start() -> AsyncStream<UInt32?> {
        pair.stream
    }

    /// Delivers fixture input through the injected port.
    public func send(consoleUID: UInt32?) {
        pair.continuation.yield(consoleUID)
    }

    /// Finishes this fixture event stream.
    public func stop() {
        pair.continuation.finish()
    }
}
