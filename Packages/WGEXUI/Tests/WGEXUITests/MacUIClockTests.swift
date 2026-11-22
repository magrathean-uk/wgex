// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacUIClockTests {
        private let generation = Generation(rawValue: 1)

        @Test(.timeLimit(.minutes(1)))
        func `hidden daemon silence becomes stale and a new report reschedules the deadline`() async {
            let clock = UIWorkTestClock()
            let model = model(at: clock.now)
            let work = MacUIWork(shell: model, clock: clock.dependency, announce: { _ in })
            work.observePreferences()
            await clock.settle()
            #expect(!model.presentation.isStale)
            clock.advance(by: Staleness.threshold - 1)
            model.receive(status(.active(generation)), at: clock.now)
            await clock.settle()
            clock.advance(by: 2)
            await clock.settle()
            #expect(!model.presentation.isStale)
            clock.advance(by: Staleness.threshold)
            await clock.settle()
            #expect(model.presentation.isStale)
            #expect(model.presentation.primary == "Service not responding")
            work.stop()
            await clock.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `composition sends no statistics while hidden or outside the live phase list`() async {
            let clock = UIWorkTestClock()
            let model = model(at: clock.now)
            var requests = 0
            let work = MacUIWork(shell: model, clock: clock.dependency, sample: { requests += 1 }, announce: { _ in })
            work.observePreferences()
            clock.advance(by: 30)
            await clock.settle()
            #expect(requests == 0)
            work.visibility(true, surface: "main")
            await clock.settle()
            #expect(requests == 1)
            work.visibility(true, surface: "menu")
            await clock.settle()
            #expect(requests == 1)
            for phase in [
                TunnelPhase.reasserting(generation, reason: .wake),
                .captiveWindow(generation, expires: clock.now.addingTimeInterval(300)),
            ] {
                model.receive(status(phase), at: clock.now)
                await clock.settle()
                clock.advance(by: 2)
                await clock.settle()
            }
            #expect(requests == 3)
            work.visibility(false, surface: "main")
            work.visibility(false, surface: "menu")
            await clock.settle()
            clock.advance(by: 30)
            await clock.settle()
            #expect(requests == 3)
            model.receive(status(.preparing(generation)), at: clock.now)
            work.visibility(true, surface: "settings")
            await clock.settle()
            clock.advance(by: 30)
            await clock.settle()
            #expect(requests == 3)
            work.stop()
            await clock.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `session start is the active transition even if all surfaces are hidden`() async {
            let clock = UIWorkTestClock()
            let model = model(at: clock.now, phase: .idle)
            let work = MacUIWork(shell: model, clock: clock.dependency, announce: { _ in })
            work.observePreferences()
            #expect(model.connectedDuration == "Unavailable")
            clock.advance(by: 20)
            model.receive(status(.active(generation)), at: clock.now)
            await clock.settle()
            #expect(model.traffic.startedAt == clock.now)
            clock.advance(by: 3600)
            model.tick(at: clock.now)
            #expect(model.connectedDuration == "1 h")
            model.receive(status(.reasserting(generation, reason: .wake)), at: clock.now)
            await clock.settle()
            model.receive(status(.active(generation)), at: clock.now)
            await clock.settle()
            #expect(model.connectedDuration == "1 h")
            work.stop()
            await clock.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `an active first report cannot establish when the session actually began`() async {
            let clock = UIWorkTestClock()
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                now: clock.now,
            )
            let work = MacUIWork(shell: model, clock: clock.dependency, announce: { _ in })
            work.observePreferences()
            clock.advance(by: 10)
            model.receive(status(.active(generation)), at: clock.now)
            await clock.settle()
            #expect(model.traffic.startedAt == nil)
            #expect(model.connectedDuration == "Unavailable")
            work.stop()
            await clock.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `an already active session has an unknown start and visibility shares one display tick`() async {
            let clock = UIWorkTestClock()
            let model = model(at: clock.now)
            let work = MacUIWork(shell: model, clock: clock.dependency, sample: {}, announce: { _ in })
            work.observePreferences()
            #expect(model.connectedDuration == "Unavailable")
            work.visibility(true, surface: "main")
            work.visibility(true, surface: "menu")
            await clock.settle()
            #expect(clock.waiters.filter { $0.interval == 1 }.count == 1)
            work.visibility(false, surface: "main")
            clock.advance(by: 1)
            await clock.settle()
            #expect(model.now == clock.now)
            #expect(clock.waiters.filter { $0.interval == 1 }.count == 1)
            work.visibility(false, surface: "menu")
            await clock.settle()
            #expect(clock.waiters.filter { $0.interval == 1 }.isEmpty)
            work.stop()
            await clock.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `termination replies after flush or the one second cap exactly once`() async {
            for completes in [false, true] {
                let clock = UIWorkTestClock()
                let termination = MacTerminationFlush(clock: clock.dependency)
                let (saved, continuation) = AsyncStream<Void>.makeStream()
                var replies = 0
                termination.start(flush: {
                    var iterator = saved.makeAsyncIterator()
                    await iterator.next()
                }, reply: { replies += 1 })
                await clock.settle()
                #expect(replies == 0)
                if completes {
                    continuation.yield(())
                } else {
                    clock.advance(by: 1)
                }
                await clock.settle()
                #expect(replies == 1)
                continuation.finish()
                clock.advance(by: 2)
                await clock.settle()
                #expect(replies == 1)
                await clock.finish()
            }
        }

        private func model(at date: Date, phase: TunnelPhase? = nil) -> MacShellModel {
            MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                status: status(phase ?? .active(generation)),
                now: date,
            )
        }

        private func status(_ phase: TunnelPhase) -> TunnelStatus {
            .init(phase: phase, protection: .protected, transport: nil, health: .idle, recentEvents: [])
        }
    }

    @MainActor
    private final class UIWorkTestClock {
        struct Waiter {
            let id: UUID
            let interval: TimeInterval
            let deadline: Date
            let continuation: CheckedContinuation<Void, any Error>
        }

        var now = Date(timeIntervalSince1970: 1_800_000_000)
        var waiters: [Waiter] = []
        var dependency: MacUIClock {
            MacUIClock(now: { self.now }, sleep: { interval in try await self.sleep(interval) })
        }

        func sleep(_ interval: TimeInterval) async throws {
            let id = UUID()
            try await withTaskCancellationHandler {
                try Task.checkCancellation()
                try await withCheckedThrowingContinuation { continuation in
                    waiters.append(Waiter(
                        id: id,
                        interval: interval,
                        deadline: now.addingTimeInterval(interval),
                        continuation: continuation,
                    ))
                }
            } onCancel: {
                Task { @MainActor in self.cancel(id) }
            }
        }

        func cancel(_ id: UUID) {
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
            waiters.remove(at: index).continuation.resume(throwing: CancellationError())
        }

        func advance(by interval: TimeInterval) {
            now.addTimeInterval(interval)
            let ready = waiters.filter { $0.deadline <= now }
            waiters.removeAll { $0.deadline <= now }
            for waiter in ready {
                waiter.continuation.resume()
            }
        }

        func settle() async {
            for _ in 0 ..< 100 {
                await Task.yield()
            }
        }

        func finish() async {
            await settle()
            for waiter in waiters {
                waiter.continuation.resume(throwing: CancellationError())
            }
            waiters = []
        }
    }
#endif
