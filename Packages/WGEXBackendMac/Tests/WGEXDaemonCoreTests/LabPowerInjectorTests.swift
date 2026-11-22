// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Darwin
    import Foundation
    import Synchronization
    import Testing
    @testable import WGEXDaemonCore
    import WGEXDaemonCoreTesting
    import WGEXDaemonProtocol

    /// The test double for the injection trigger: most tests use this instead of process-wide signals.
    /// `fire` calls the delivery closure the injector installed, also after `stop` (a handler already in flight when the
    /// sources are cancelled), so a test can show the injector ignores it.
    package final class ManualPowerTrigger: LabPowerInjectorTrigger {
        private struct State { var deliver: (@Sendable (PowerEvent) -> Void)?; var starts = 0; var stops = 0 }
        private let state = Mutex(State())
        package init() {}
        package var starts: Int {
            state.withLock { $0.starts }
        }

        package var stops: Int {
            state.withLock { $0.stops }
        }

        package var installed: Bool {
            state.withLock { $0.deliver != nil }
        }

        package func start(deliver: @escaping @Sendable (PowerEvent) -> Void) {
            state.withLock { $0.deliver = deliver; $0.starts += 1 }
        }

        package func stop() {
            state.withLock { $0.stops += 1 }
        }

        package func fire(_ event: PowerEvent) {
            let deliver = state.withLock { $0.deliver }
            deliver?(event)
        }
    }

    /// The injector's log sink, one entry per line.
    package final class InjectedLines: Sendable {
        private let lines = Mutex<[String]>([])
        package init() {}
        package var all: [String] {
            lines.withLock { $0 }
        }

        package func record(_ line: String) {
            lines.withLock { $0.append(line) }
        }
    }

    /// A restartable inner monitor that counts its starts and stops (the fake monitor has one stream for its lifetime).
    package actor CountingPowerMonitor: PowerMonitoring {
        private var sink: AsyncStream<PowerEvent>.Continuation?
        package private(set) var starts = 0
        package private(set) var stops = 0
        package init() {}
        package func start() -> AsyncStream<PowerEvent> {
            starts += 1
            let pair = AsyncStream<PowerEvent>.makeStream(bufferingPolicy: .bufferingNewest(16))
            sink = pair.continuation
            return pair.stream
        }

        package func send(_ event: PowerEvent) {
            sink?.yield(event)
        }

        package func stop() {
            stops += 1; sink?.finish(); sink = nil
        }
    }

    @Suite(.timeLimit(.minutes(1)))
    private struct LabPowerInjectorTests {
        private func injector(
            inner: any PowerMonitoring, trigger: ManualPowerTrigger, lines: InjectedLines, labHost: Bool = true,
        ) -> LabPowerInjector {
            LabPowerInjector(inner: inner, trigger: trigger, isLabHost: { labHost }, log: { lines.record($0) })
        }

        @Test
        func `injected sleep and wake reach the stream in order`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines()
            let monitor = injector(inner: FakePowerMonitor(), trigger: trigger, lines: lines)
            var events = try await monitor.start().makeAsyncIterator()
            #expect(trigger.starts == 1)
            trigger.fire(.sleep)
            trigger.fire(.wake)
            #expect(await events.next() == .sleep)
            #expect(await events.next() == .wake)
            await monitor.stop()
        }

        @Test
        func `injected events interleave with the inner monitor's events in arrival order`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines(), inner = FakePowerMonitor()
            let monitor = injector(inner: inner, trigger: trigger, lines: lines)
            var events = try await monitor.start().makeAsyncIterator()
            var received: [PowerEvent?] = []
            // Each step waits for its event, so the arrival order is the program order of the steps.
            inner.send(.sleep); await received.append(events.next())
            trigger.fire(.wake); await received.append(events.next())
            trigger.fire(.sleep); await received.append(events.next())
            inner.send(.wake); await received.append(events.next())
            inner.send(.sleep); await received.append(events.next())
            trigger.fire(.wake); await received.append(events.next())
            #expect(received == [.sleep, .wake, .sleep, .wake, .sleep, .wake])
            // Only the three injected events are logged; the inner monitor's events carry no injection line.
            #expect(lines.all == ["lab power inject wake", "lab power inject sleep", "lab power inject wake"])
            await monitor.stop()
        }

        @Test
        func `nothing is injected and nothing is logged unless the guard says a lab host`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines(), inner = FakePowerMonitor()
            let monitor = injector(inner: inner, trigger: trigger, lines: lines, labHost: false)
            var events = try await monitor.start().makeAsyncIterator()
            #expect(trigger.starts == 0, "no signal source is installed off a lab host")
            #expect(!trigger.installed)
            trigger.fire(.sleep); trigger.fire(.wake)
            inner.send(.wake)
            #expect(await events.next() == .wake, "the inner monitor's events still pass through, as without the wrapper")
            await monitor.stop()
            #expect(await events.next() == nil, "no injected event was queued behind the inner one")
            #expect(lines.all.isEmpty)
        }

        @Test
        func `stop tears down both sources and ignores a late injection`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines(), inner = CountingPowerMonitor()
            let monitor = injector(inner: inner, trigger: trigger, lines: lines)
            var events = try await monitor.start().makeAsyncIterator()
            #expect(await inner.starts == 1)
            trigger.fire(.sleep)
            #expect(await events.next() == .sleep)
            await monitor.stop()
            #expect(trigger.stops == 1)
            #expect(await inner.stops == 1)
            #expect(await events.next() == nil, "the merged stream finishes with the sources")
            trigger.fire(.wake)
            #expect(lines.all == ["lab power inject sleep"], "an injection after stop is neither logged nor delivered")
            await monitor.stop()
            #expect(trigger.stops == 1, "a second stop releases the trigger only once")
            #expect(await inner.stops == 2, "the inner monitor hears every stop, as without the wrapper (its stop is idempotent)")
        }

        @Test
        func `the monitor restarts after stop as the network monitoring restart does`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines(), inner = CountingPowerMonitor()
            let monitor = injector(inner: inner, trigger: trigger, lines: lines)
            _ = try await monitor.start()
            await monitor.stop()
            var events = try await monitor.start().makeAsyncIterator()
            #expect(trigger.starts == 2)
            trigger.fire(.wake)
            #expect(await events.next() == .wake)
            await inner.send(.sleep)
            #expect(await events.next() == .sleep)
            await monitor.stop()
            #expect(trigger.stops == 2)
            #expect(await inner.stops == 2)
        }

        @Test
        func `each injected event logs one fixed line without any other text`() {
            #expect(LabPowerInjector.line(for: .sleep) == "lab power inject sleep")
            #expect(LabPowerInjector.line(for: .wake) == "lab power inject wake")
        }

        @Test
        func `the signal adapter maps SIGUSR1 to sleep and SIGUSR2 to wake only`() {
            #expect(LabPowerInjectorSignals.event(forSignal: SIGUSR1) == .sleep)
            #expect(LabPowerInjectorSignals.event(forSignal: SIGUSR2) == .wake)
            for other in [SIGTERM, SIGINT, SIGHUP, SIGUSR1 + 100] {
                #expect(LabPowerInjectorSignals.event(forSignal: other) == nil)
            }
        }

        @Test
        func `the forwarder finishes the merged stream when the inner stream ends without stopping the injector`() async throws {
            let trigger = ManualPowerTrigger(), lines = InjectedLines(), inner = CountingPowerMonitor()
            let monitor = injector(inner: inner, trigger: trigger, lines: lines)
            let stream = try await monitor.start()
            let finished = Mutex(false)
            let reader = Task {
                for await _ in stream {}
                finished.withLock { $0 = true }
            }
            await inner.stop()
            let deadline = ContinuousClock.now + .seconds(2)
            while !finished.withLock({ $0 }), ContinuousClock.now < deadline {
                try await Task.sleep(for: .milliseconds(10))
            }
            #expect(finished.withLock { $0 }, "inner completion must finish the merged stream without injector.stop()")
            reader.cancel()
            await monitor.stop()
            await reader.value
        }

        #if os(macOS)
            /// These tests share process-wide signal dispositions and sources; serialize their signal delivery.
            @Suite(.serialized)
            private struct SignalAdapterTests {
                /// kqueue registration may follow resume(). Retry until observed, with a hard two-second deadline.
                private func signalUntil(_ number: Int32, delivered: () -> Bool) async throws -> Bool {
                    let deadline = ContinuousClock.now + .seconds(2)
                    while !delivered(), ContinuousClock.now < deadline {
                        #expect(kill(getpid(), number) == 0)
                        try await Task.sleep(for: .milliseconds(10))
                    }
                    return delivered()
                }

                @Test
                func `the signal adapter delivers sleep and wake and survives a signal after stop`() async throws {
                    // Signals this test process itself only. SIG_IGN keeps missing sources harmless.
                    let adapter = LabPowerInjectorSignals()
                    defer { adapter.stop() }
                    let received = Mutex<[PowerEvent]>([])
                    adapter.start { event in received.withLock { $0.append(event) } }
                    #expect(try await signalUntil(SIGUSR1) { received.withLock { $0.contains(.sleep) } })
                    #expect(try await signalUntil(SIGUSR2) { received.withLock { $0.contains(.wake) } })
                    adapter.stop()
                    #expect(kill(getpid(), SIGUSR1) == 0)
                    #expect(kill(getpid(), SIGUSR2) == 0)
                }

                @Test
                func `real signal sources are removed so injection works after an adapter restart`() async throws {
                    let adapter = LabPowerInjectorSignals(), inner = CountingPowerMonitor(), lines = InjectedLines()
                    defer { adapter.stop() }
                    let monitor = LabPowerInjector(inner: inner, trigger: adapter, isLabHost: { true }, log: { lines.record($0) })
                    var first = try await monitor.start().makeAsyncIterator()
                    let slept = try await signalUntil(SIGUSR1) { lines.all.contains("lab power inject sleep") }
                    if slept {
                        #expect(await first.next() == .sleep)
                    }
                    #expect(slept)
                    await monitor.stop()
                    var restarted = try await monitor.start().makeAsyncIterator()
                    let woke = try await signalUntil(SIGUSR2) { lines.all.contains("lab power inject wake") }
                    if woke {
                        #expect(await restarted.next() == .wake)
                    }
                    #expect(woke, "restart must install a new delivery closure, not retain the cancelled session's sources")
                    await monitor.stop()
                    #expect(await inner.starts == 2)
                    #expect(await inner.stops == 2)
                }
            }

            @Test
            func `Lab makeMonitors composes the system power monitor through the injector without starting adapters`() throws {
                let harness = try ControllerHarness()
                let monitors = makeMonitors(
                    controller: harness.controller,
                    journal: harness.journal,
                    runtime: DaemonRuntime(),
                    log: { _ in },
                )
                // Inspect the immutable composition only. Starting these real adapters belongs to the guest.
                let power = try #require(Mirror(reflecting: monitors).children.first { $0.label == "power" })
                #expect(power.value is LabPowerInjector)
            }
        #endif

        @Test
        func `a failing inner start leaves no signal source installed`() async {
            struct Failing: PowerMonitoring {
                func start() async throws -> AsyncStream<PowerEvent> {
                    throw DaemonFailure.hostLabRequired
                }

                func stop() async {}
            }
            let trigger = ManualPowerTrigger()
            let monitor = injector(inner: Failing(), trigger: trigger, lines: InjectedLines())
            await #expect(throws: DaemonFailure.hostLabRequired) { _ = try await monitor.start() }
            #expect(trigger.starts == 0)
        }
    }
#endif
