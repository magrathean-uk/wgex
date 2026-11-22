// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Foundation
    import os
    import Synchronization
    import WGEXDaemonProtocol
    #if os(macOS)
        import Darwin
        import Dispatch
    #endif

    /// Where injected power events come from (M1-47). The daemon's adapter is ``LabPowerInjectorSignals``; host tests drive the
    /// injector through a manual trigger; adapter tests signal only their own test process.
    package protocol LabPowerInjectorTrigger: Sendable {
        /// Starts delivering injected events to `deliver`, which may be called from any thread until `stop`.
        func start(deliver: @escaping @Sendable (PowerEvent) -> Void)
        /// Releases whatever `start` acquired. Safe to call more than once.
        func stop()
    }

    /// Lab-only power-event injection (M1-47): wraps a ``PowerMonitoring`` and returns one stream holding the inner monitor's
    /// events and the injected ones, in arrival order. The Lab VM cannot sleep (`pmset sleepnow` is unavailable), so the
    /// POWER-WAKE row injects the daemon's own sleep and wake events instead; the guest, its network stack and its WireGuard
    /// timers do not sleep.
    ///
    /// The whole file is compiled only with `WGEX_LAB_BUILD`, and nothing is injected unless ``LabGuard/isLabHost()`` holds when
    /// the monitor starts; off a lab host the wrapper installs no source and passes the inner events through untouched. Each
    /// injected event logs one fixed line (``line(for:)``), never any profile or system data, for the harness to find.
    package actor LabPowerInjector: PowerMonitoring {
        private final class Session: Sendable {
            let continuation: AsyncStream<PowerEvent>.Continuation
            let live = Mutex(true)
            let triggerStarted: Bool
            let forwarder = Mutex<Task<Void, Never>?>(nil)
            init(continuation: AsyncStream<PowerEvent>.Continuation, triggerStarted: Bool) {
                self.continuation = continuation; self.triggerStarted = triggerStarted
            }
        }

        private let inner: any PowerMonitoring
        private let trigger: any LabPowerInjectorTrigger
        private let isLabHost: @Sendable () -> Bool
        private let log: @Sendable (String) -> Void
        private var session: Session?

        /// The stable text of one injected event's log line, for the harness (`lab power inject sleep|wake`).
        package static func line(for event: PowerEvent) -> String {
            switch event {
            case .sleep: "lab power inject sleep"
            case .wake: "lab power inject wake"
            }
        }

        /// Unified-log writer in the Lab subsystem, as the other Lab diagnostics lines use.
        package static let systemLog: @Sendable (String) -> Void = { line in
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").log("\(line, privacy: .public)")
        }

        /// The injector seam: every collaborator is replaceable, none is reachable from the environment.
        package init(
            inner: any PowerMonitoring, trigger: any LabPowerInjectorTrigger,
            isLabHost: @escaping @Sendable () -> Bool = { LabGuard.isLabHost() },
            log: @escaping @Sendable (String) -> Void = LabPowerInjector.systemLog,
        ) {
            self.inner = inner; self.trigger = trigger; self.isLabHost = isLabHost; self.log = log
        }

        #if os(macOS)
            /// The daemon's wiring: SIGUSR1 injects a sleep and SIGUSR2 a wake.
            package init(inner: any PowerMonitoring) {
                self.init(inner: inner, trigger: LabPowerInjectorSignals())
            }
        #endif

        /// Starts the inner monitor first, so its failure leaves no source installed, then the injection trigger on a lab host.
        package func start() async throws -> AsyncStream<PowerEvent> {
            guard session == nil else { throw DaemonFailure.hostAlreadyStarted }
            let innerEvents = try await inner.start()
            let pair = AsyncStream<PowerEvent>.makeStream(bufferingPolicy: .bufferingNewest(16))
            let injecting = isLabHost()
            let session = Session(continuation: pair.continuation, triggerStarted: injecting)
            if injecting {
                let log = log
                trigger.start { event in
                    guard session.live.withLock({ $0 }) else { return }
                    log(Self.line(for: event))
                    session.continuation.yield(event)
                }
            }
            session.forwarder.withLock { task in
                task = Task {
                    for await event in innerEvents {
                        session.continuation.yield(event)
                    }
                    // The inner stream ended (stopped or failed): the merged one ends with it, as the unwrapped monitor's would.
                    session.continuation.finish()
                }
            }
            self.session = session
            return pair.stream
        }

        /// Tears down both sources. The inner monitor always hears it, as without the wrapper (its stop is idempotent and a
        /// failed start still needs it).
        package func stop() async {
            if let current = session {
                session = nil
                current.live.withLock { $0 = false }
                if current.triggerStarted {
                    trigger.stop()
                }
                current.forwarder.withLock { $0?.cancel() }
                current.continuation.finish()
            }
            await inner.stop()
        }
    }

    #if os(macOS)
        /// The daemon's injection adapter: SIGUSR1 is a sleep and SIGUSR2 a wake. Only root can signal the root daemon, so this
        /// adds no XPC surface and no client. The default action of both signals ends the process, so both are ignored from
        /// construction (the daemon builds its monitors before it listens, so before any client can ask for a tunnel) and stay
        /// ignored afterwards: a stray signal before the sources start, or during shutdown, must not kill the daemon.
        /// This sets SIG_IGN in every Lab daemon, including off a lab host: the host guard gates event delivery, not signal
        /// disposition. Otherwise moving the ignore into start() would leave a fatal window before registration or after stop().
        /// Ignored dispositions normally survive across exec. On this macOS, Foundation Process resets them to SIG_DFL:
        /// a host C sigaction probe confirmed both the direct spawn and the stdin-gated shell exec used for pfctl (empty
        /// environment, as in PFProcessExecutor). Process-spawned pfctl therefore does not inherit SIG_IGN; no pf change is
        /// needed. Release and ordinary Debug builds compile none of this adapter.
        package final class LabPowerInjectorSignals: LabPowerInjectorTrigger {
            private let queue = DispatchQueue(label: "WGEX.lab.power-inject")
            private let sources = Mutex<[any DispatchSourceSignal]>([])
            package init() {
                signal(SIGUSR1, SIG_IGN)
                signal(SIGUSR2, SIG_IGN)
            }

            /// SIGUSR1 is a sleep, SIGUSR2 a wake, and nothing else is an injection.
            package static func event(forSignal number: Int32) -> PowerEvent? {
                switch number {
                case SIGUSR1: .sleep
                case SIGUSR2: .wake
                default: nil
                }
            }

            package func start(deliver: @escaping @Sendable (PowerEvent) -> Void) {
                sources.withLock { held in
                    guard held.isEmpty else { return }
                    for number in [SIGUSR1, SIGUSR2] {
                        let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
                        let handler: @Sendable () -> Void = {
                            if let event = Self.event(forSignal: number) {
                                deliver(event)
                            }
                        }
                        source.setEventHandler(handler: handler)
                        source.resume()
                        held.append(source)
                    }
                }
            }

            package func stop() {
                sources.withLock { held in
                    for source in held {
                        source.cancel()
                    }
                    held = []
                }
            }
        }
    #endif
#endif
