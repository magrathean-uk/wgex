// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXPolicy

private final class TestHealthClock: HealthClock {
    private let time = Mutex<Duration>(.zero)
    fileprivate var now: Duration {
        time.withLock { $0 }
    }

    fileprivate func advance(_ duration: Duration) {
        time.withLock { $0 += duration }
    }
}

private struct HealthEvaluatorTests {
    @Test
    func `thirty minutes idle without keepalive remains idle without a probe`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        clock.advance(.seconds(1800))
        #expect(evaluator.evaluate().level == .idle)
        #expect(evaluator.evaluate().requests.isEmpty)
    }

    @Test
    func `twenty seconds after engine no response event is unresponsive after the probe`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        // EngineEvent.txWithoutRx already reports a completed 15-second window.
        let first = evaluator.consume(.txWithoutRx(since: .seconds(-15)))
        #expect(first.level == .degraded(reason: "txWithoutRx"))
        #expect(first.requests == [.forceHandshake])
        clock.advance(.seconds(20))
        let result = evaluator.evaluate()
        #expect(result.level == .unresponsive)
        #expect(result.requests.isEmpty)
    }

    @Test
    func `unresponsive requires the next complete window and probe grace`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        #expect(evaluator.consume(.txWithoutRx(since: .seconds(-15))).requests == [.forceHandshake])
        clock.advance(.seconds(10))
        #expect(evaluator.evaluate().level == .degraded(reason: "txWithoutRx"))
        clock.advance(.seconds(5))
        #expect(evaluator.evaluate().level == .unresponsive)
    }

    @Test
    func `a delayed evaluation emits a probe before unresponsive judgement`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock, path: .unsatisfied)
        #expect(evaluator.consume(.txWithoutRx(since: .seconds(-15))).level == .offline)
        clock.advance(.seconds(200))
        let first = evaluator.updatePath(.satisfied)
        #expect(first.level == .degraded(reason: "txWithoutRx"))
        #expect(first.requests == [.forceHandshake])
        clock.advance(.seconds(9))
        #expect(evaluator.evaluate().level == .degraded(reason: "txWithoutRx"))
        clock.advance(.seconds(1))
        #expect(evaluator.evaluate().level == .unresponsive)
    }

    @Test
    func `unsatisfied path remains offline through receive handshake and carrier changes`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        #expect(evaluator.updatePath(.unsatisfied).level == .offline)
        #expect(evaluator.consume(.rx).level == .offline)
        #expect(evaluator.consume(.handshakeCompleted(at: Date())).level == .offline)
        #expect(evaluator.updateCarrier(.disconnected).level == .offline)
        #expect(evaluator.updateCarrier(.connected).level == .offline)
        clock.advance(.seconds(1800))
        #expect(evaluator.evaluate().level == .offline)
        #expect(evaluator.updatePath(.satisfied).level == .idle)
    }

    @Test
    func `one good window recovers from unresponsive`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        _ = evaluator.consume(.txWithoutRx(since: .seconds(-15)))
        clock.advance(.seconds(20))
        #expect(evaluator.evaluate().level == .unresponsive)
        #expect(evaluator.consume(.rx).level == .degraded(reason: "recovering"))
        clock.advance(.seconds(14))
        #expect(evaluator.consume(.rx).level == .degraded(reason: "recovering"))
        clock.advance(.seconds(1))
        #expect(evaluator.evaluate().level == .healthy)
    }

    @Test
    func `handshake resets all windows and permits a new probe episode`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        _ = evaluator.consume(.txWithoutRx(since: .seconds(-15)))
        clock.advance(.seconds(30))
        #expect(evaluator.evaluate().level == .unresponsive)
        let date = Date(timeIntervalSince1970: 123)
        let recovered = evaluator.consume(.handshakeCompleted(at: date))
        #expect(recovered.level == .healthy); #expect(recovered.lastHandshake == date)
        #expect(evaluator.consume(.txWithoutRx(since: clock.now)).requests == [.forceHandshake])
        #expect(evaluator.consume(.txWithoutRx(since: clock.now)).requests.isEmpty)
    }

    @Test
    func `duplicate engine events neither reset nor accelerate windows`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        _ = evaluator.consume(.txWithoutRx(since: .seconds(-15)))
        for _ in 0 ..< 100 {
            #expect(evaluator.consume(.txWithoutRx(since: .seconds(-15))).requests.isEmpty)
        }
        #expect(evaluator.evaluate().level == .degraded(reason: "txWithoutRx"))
        clock.advance(.seconds(15))
        #expect(evaluator.consume(.txWithoutRx(since: .seconds(-15))).level == .unresponsive)
    }

    @Test
    func `carrier failures cannot report healthy until reconnected`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        #expect(evaluator.updateCarrier(.disconnected).level == .degraded(reason: "carrierUnavailable"))
        #expect(evaluator.consume(.handshakeCompleted(at: Date())).level == .degraded(reason: "carrierUnavailable"))
        #expect(evaluator.updateCarrier(.connected).level == .healthy)
    }

    @Test
    func `returning path requires a new probe before stale failure judgement`() {
        let clock = TestHealthClock(); var evaluator = HealthEvaluator(clock: clock)
        _ = evaluator.consume(.txWithoutRx(since: .seconds(-15)))
        _ = evaluator.updatePath(.unsatisfied); clock.advance(.seconds(100))
        let resumed = evaluator.updatePath(.satisfied)
        #expect(resumed.requests == [.forceHandshake])
        #expect(resumed.level == .degraded(reason: "txWithoutRx"))
        #expect(resumed.txWithoutRxSince == .seconds(-15))
        clock.advance(.seconds(10))
        #expect(evaluator.evaluate().level == .unresponsive)
    }

    @Test
    func `custom thresholds preserve the legacy initializer and control judgement`() {
        let clock = TestHealthClock()
        var thresholds = HealthThresholds(txWithoutRxWindow: .seconds(2), idleAfter: .seconds(5), unresponsiveWindows: 3)
        thresholds.probeGrace = .seconds(6); thresholds.recoveryWindow = .seconds(2)
        var evaluator = HealthEvaluator(clock: clock, thresholds: thresholds)
        _ = evaluator.consume(.txWithoutRx(since: .seconds(-2)))
        clock.advance(.seconds(4))
        #expect(evaluator.evaluate().level == .degraded(reason: "txWithoutRx"))
        clock.advance(.seconds(2))
        #expect(evaluator.evaluate().level == .unresponsive)
        _ = evaluator.consume(.rx); clock.advance(.seconds(2))
        #expect(evaluator.evaluate().level == .healthy)
        _ = evaluator.consume(.transmitted); clock.advance(.seconds(5))
        #expect(evaluator.evaluate().level == .idle)
    }
}
