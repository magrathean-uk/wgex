// SPDX-License-Identifier: MIT
import Foundation

public enum PowerEvent: Sendable, Equatable { case sleep, wake }

public protocol PowerMonitoring: Sendable {
    func start() async throws -> AsyncStream<PowerEvent>
    func stop() async
}

public struct WakeDecision: Sendable, Equatable {
    public let bumpSockets: Bool
    public let forceHandshake: Bool
}

public struct PowerMonitorModel: Sendable {
    private var sleptAt: Duration?
    public private(set) var awaitingHandshake = false
    public init() {}
    public mutating func sleep(at now: Duration) {
        sleptAt = now
    }

    public mutating func wake(at now: Duration, wallNow: Date, lastHandshake: Date?) -> WakeDecision {
        let sleepDelta = sleptAt.map { now - $0 }
        // An undetermined sleep or handshake age is treated conservatively.
        let force = (sleepDelta.map { $0 > .seconds(5) } ?? true)
            || (lastHandshake.map { wallNow.timeIntervalSince($0) > 110 } ?? true)
        sleptAt = nil; awaitingHandshake = force
        return WakeDecision(bumpSockets: true, forceHandshake: force)
    }

    public mutating func handshakeCompleted() {
        awaitingHandshake = false
    }
}
