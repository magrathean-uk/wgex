// SPDX-License-Identifier: MIT
import Foundation

public protocol PairingClock: Sendable {
    var now: Duration { get }
    func sleep(until deadline: Duration) async throws
}

public struct ContinuousPairingClock: PairingClock {
    private let origin = ContinuousClock.now
    public init() {}
    public var now: Duration {
        origin.duration(to: .now)
    }

    public func sleep(until deadline: Duration) async throws {
        try await ContinuousClock().sleep(until: origin.advanced(by: deadline))
    }
}
