// SPDX-License-Identifier: MIT

import Synchronization

/// Arms errors at named points; fakes consume them where they would fail.
public final class FaultInjector: Sendable {
    /// A named fault point, for example `"start"`.
    public struct Point: Hashable, Sendable, ExpressibleByStringLiteral {
        /// Point name.
        public let rawValue: String

        /// Creates a point.
        public init(_ rawValue: String) {
            self.rawValue = rawValue
        }

        /// Creates a point from a literal.
        public init(stringLiteral value: String) {
            rawValue = value
        }
    }

    private struct State {
        var armed: [Point: [any Error & Sendable]] = [:]
        var triggered: [Point: Int] = [:]
    }

    private let state = Mutex(State())

    /// Creates an injector with nothing armed.
    public init() {}

    /// Arms `error` at `point` for the next `times` hits.
    public func arm(_ point: Point, error: any Error & Sendable, times: Int = 1) {
        state.withLock { $0.armed[point, default: []] += Array(repeating: error, count: max(0, times)) }
    }

    /// Removes everything armed at `point`.
    public func disarm(_ point: Point) {
        state.withLock { _ = $0.armed.removeValue(forKey: point) }
    }

    /// Consumes the next armed error at `point` when it is a `Failure`.
    public func fault<Failure: Error>(at point: Point, as _: Failure.Type) -> Failure? {
        state.withLock { state in
            guard let next = state.armed[point]?.first as? Failure else { return nil }
            state.armed[point]?.removeFirst()
            state.triggered[point, default: 0] += 1
            return next
        }
    }

    /// How many armed errors were consumed at `point`.
    public func triggerCount(at point: Point) -> Int {
        state.withLock { $0.triggered[point] ?? 0 }
    }
}
