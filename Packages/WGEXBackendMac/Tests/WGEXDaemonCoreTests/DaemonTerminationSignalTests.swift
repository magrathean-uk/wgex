// SPDX-License-Identifier: MIT
#if os(macOS)
    import Darwin
    import Dispatch
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    @testable import WGEXDaemonCore

    @Suite(.serialized, .timeLimit(.minutes(1)))
    private struct DaemonTerminationSignalTests {
        @Test(arguments: [SIGTERM, SIGINT]) @MainActor
        func `real SIGTERM from a non main queue reaches the production dispatch source`(_ signalNumber: Int32) async throws {
            let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
            let runtime = DaemonRuntime(clock: HostClock()), trace = HostTrace()
            let messages = Mutex<[DaemonRuntimeMessage]>([])
            await runtime.run(ports: .init(
                startListener: {}, setRecovering: { _ in }, reconcile: {}, startMonitors: {}, block: { _ in },
                shouldRetry: { true }, shutdown: { try await h.controller.shutdownCleanly(); try trace.record("shutdown") },
            ))
            let previous = signal(SIGTERM, SIG_IGN), previousINT = signal(SIGINT, SIG_IGN)
            let termination = terminationSource(runtime: runtime, refresh: {}, log: { value in messages.withLock { $0.append(value) } })
            defer {
                termination.source.cancel(); termination.interruptSource.cancel()
                _ = signal(SIGTERM, previous); _ = signal(SIGINT, previousINT)
            }
            let source = signalNumber == SIGTERM ? termination.source : termination.interruptSource
            await withCheckedContinuation { continuation in
                let registered: @Sendable () -> Void = { continuation.resume() }
                source.setRegistrationHandler(handler: registered)
                source.resume()
            }
            if signalNumber == SIGTERM {
                termination.interruptSource.resume()
            } else {
                termination.source.resume()
            }
            let result = Mutex<Int32?>(nil)
            DispatchQueue.global().async {
                result.withLock { $0 = kill(getpid(), signalNumber) }
            }
            var events = termination.events.makeAsyncIterator()
            #expect(await events.next() != nil)
            #expect(result.withLock { $0 } == 0)
            #expect(trace.calls == ["shutdown"])
            let data = try #require(try h.directory.read("journal.json"))
            let checkpoint = try JSONDecoder().decode(DaemonJournalDocument.self, from: data)
            #expect(checkpoint.cleanShutdownAt != nil && checkpoint.pfToken != nil)
            #expect(checkpoint.resources == h.journal.snapshot().resources)
            #expect(messages.withLock { $0.map(\.rawValue) }.contains("Orderly shutdown completed; checkpoint written"))
        }

        @Test
        func `termination wins the startup race and drains recovery without restarting it`() async {
            let runtime = DaemonRuntime(clock: HostClock()), gate = StepGate(point: .verify), trace = HostTrace()
            let events = AsyncStream<Void>.makeStream()
            let serving = Task {
                await runtime.serveUntilTermination(events: events.stream, startup: {
                    await runtime.run(ports: .init(
                        startListener: {}, setRecovering: { _ in }, reconcile: { try trace.record("reconcile") },
                        startMonitors: { try await gate.before(.verify, generation: .initial) }, block: { _ in },
                        shouldRetry: { true }, shutdown: { try trace.record("shutdown") },
                    ))
                }, mainLoop: { try? trace.record("loop") })
            }
            await gate.wait()
            await runtime.terminate(refreshUnderlay: {}, waiting: {})
            events.continuation.yield(()); events.continuation.finish()
            await gate.release(); await serving.value
            #expect(trace.calls == ["shutdown"])
        }
    }
#endif
