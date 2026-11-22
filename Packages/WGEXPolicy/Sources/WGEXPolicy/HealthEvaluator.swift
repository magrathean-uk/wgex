// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Monotonic elapsed time; callers supply a clock without introducing timers or I/O into policy.
public protocol HealthClock: Sendable {
    var now: Duration { get }
}

/// Projection of EngineEvent, kept here to preserve the Core-only package dependency.
/// The networking owner maps engine dates to its monotonic timeline and forwards these events.
public enum HealthInput: Sendable, Hashable {
    /// The engine has already observed one complete no-response window when it emits this event.
    case txWithoutRx(since: Duration)
    case handshakeCompleted(at: Date)
    case rx
    /// Optional activity hint for accurate idle display; not a failure signal.
    case transmitted
}

public enum HealthPathState: Sendable { case satisfied, unsatisfied }
public enum HealthCarrierState: Sendable { case connected, disconnected }

public struct HealthEvaluation: Sendable, Hashable {
    public enum Request: Sendable, Hashable { case forceHandshake }
    public let level: TunnelHealth.Level
    public let lastHandshake: Date?
    /// Monotonic start supplied by the engine for the current failure episode.
    public let txWithoutRxSince: Duration?
    /// Execute each emitted request once, then evaluate again after the probe grace.
    public let requests: [Request]
}

/// Pure state machine: no sleeps, callbacks, engine dependency or side effects.
/// A delivered txWithoutRx event counts as the first completed failure window;
/// a further full window without reception counts as the second. Repeated events
/// for the same failure episode do not accelerate judgement or repeat the probe.
public struct HealthEvaluator<Time: HealthClock>: Sendable {
    private let clock: Time
    private let thresholds: HealthThresholds
    private var path: HealthPathState
    private var carrier: HealthCarrierState
    private var lastActivity: Duration
    private var failureObserved: Duration?
    private var failureSince: Duration?
    private var probeAt: Duration?
    private var recoveringAt: Duration?
    private var lastHandshake: Date?

    public init(
        clock: Time, thresholds: HealthThresholds = .standard,
        path: HealthPathState = .satisfied, carrier: HealthCarrierState = .connected,
    ) {
        self.clock = clock; self.thresholds = thresholds; self.path = path; self.carrier = carrier
        lastActivity = clock.now
    }

    public mutating func consume(_ input: HealthInput) -> HealthEvaluation {
        switch input {
        case let .txWithoutRx(since):
            lastActivity = clock.now
            if failureObserved == nil {
                failureObserved = clock.now; failureSince = min(since, clock.now)
                recoveringAt = nil
            }
        case let .handshakeCompleted(at):
            lastHandshake = at; clearFailure(); lastActivity = clock.now
        case .rx:
            lastActivity = clock.now
            if failureObserved != nil {
                clearFailure(); recoveringAt = clock.now
            }
        case .transmitted: lastActivity = clock.now
        }
        return evaluate()
    }

    public mutating func updatePath(_ path: HealthPathState) -> HealthEvaluation {
        if path == .unsatisfied {
            probeAt = nil
        }
        self.path = path
        return evaluate()
    }

    public mutating func updateCarrier(_ carrier: HealthCarrierState) -> HealthEvaluation {
        self.carrier = carrier
        return evaluate()
    }

    /// Called on events or by the networking owner's bookkeeping tick, never UI sampling.
    public mutating func evaluate() -> HealthEvaluation {
        let now = clock.now
        guard path == .satisfied else { return result(.offline) }
        guard carrier == .connected else { return result(.degraded(reason: "carrierUnavailable")) }
        if let observed = failureObserved {
            let elapsed = max(.zero, now - observed)
            let window = max(.nanoseconds(1), thresholds.txWithoutRxWindow)
            // Compare durations rather than converting to floating point or overflowing a window counter.
            let additional = max(1, thresholds.unresponsiveWindows) - 1
            let judgementAfter = window * additional
            if probeAt == nil {
                probeAt = now
                return result(.degraded(reason: "txWithoutRx"), requests: [.forceHandshake])
            }
            if let probeAt, elapsed >= judgementAfter, now - probeAt >= thresholds.probeGrace {
                return result(.unresponsive)
            }
            return result(.degraded(reason: "txWithoutRx"))
        }
        if let recoveringAt {
            guard now - recoveringAt >= thresholds.recoveryWindow else { return result(.degraded(reason: "recovering")) }
            self.recoveringAt = nil
        }
        return result(now - lastActivity >= thresholds.idleAfter ? .idle : .healthy)
    }

    private mutating func clearFailure() {
        failureObserved = nil; failureSince = nil; probeAt = nil; recoveringAt = nil
    }

    private mutating func result(_ level: TunnelHealth.Level, requests: [HealthEvaluation.Request] = []) -> HealthEvaluation {
        HealthEvaluation(level: level, lastHandshake: lastHandshake, txWithoutRxSince: failureSince, requests: requests)
    }
}
