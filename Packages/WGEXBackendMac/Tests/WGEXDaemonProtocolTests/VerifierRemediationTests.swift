// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerifierRemediationTests {
    @Test
    func `update preparation requires the actual admin right and a newer client`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 9,
            minimumClientBuild: 1,
            authorisation: .init(
                isConsoleUser: { _ in true },
                hasAdminRight: { form, _ in form == Data([1]) },
            ),
        )
        let transport = try await handshaken(dispatcher)
        #expect(try await call(transport, .prepareForUpdate) == .error(.notAuthorised(.adminRightRequired)))
        #expect(await !service.calls.contains(.prepareForUpdate))
        let envelope = try Envelope(authorization: Data([1]), body: .prepareForUpdate).encoded()
        #expect(try await WireCodec.decode(Reply.self, from: transport.send(envelope, secrets: nil)) == .ok)
        #expect(await service.calls.contains(.prepareForUpdate))
        await transport.invalidate()
    }

    @Test
    func `cancelled deadline does not begin the remote operation`() async {
        let began = Mutex(false)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await RequestDeadline().wait(for: .status, begin: { _ in began.withLock { $0 = true } }, interrupted: {})
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(!began.withLock { $0 })
    }

    @Test
    func `heartbeat timer sleeps five seconds and publishes with injected time`() async throws {
        let waits = AsyncStream<(Duration, CheckedContinuation<Void, any Error>)>.makeStream()
        let time = Mutex<TimeInterval>(100)
        let clock = XPCClock(now: { time.withLock { $0 } }, sleep: { delay in
            try await withCheckedThrowingContinuation { waits.continuation.yield((delay, $0)) }
        })
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1, clock: clock)
        let events = AsyncStream<Event>.makeStream()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: { bytes in
            if let event = try? WireCodec.decode(Event.self, from: bytes) {
                events.continuation.yield(event)
            }
        }))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        await dispatcher.startHeartbeat()
        var sleeps = waits.stream.makeAsyncIterator()
        let first = try #require(await sleeps.next())
        #expect(first.0 == .seconds(5))
        time.withLock { $0 = 105 }; first.1.resume()
        var updates = events.stream.makeAsyncIterator()
        guard case let .status(status) = await updates.next() else { Issue.record("No timed heartbeat"); return }
        #expect(status.measuredAtContinuous == 105)
        #expect(status.sequence > 0)
        let second = try #require(await sleeps.next())
        #expect(second.0 == .seconds(5))
        await dispatcher.stopHeartbeat(); second.1.resume(throwing: CancellationError())
        await transport.invalidate()
    }

    #if os(macOS)
        @Test
        func `transport applies the request deadline and invalidates without opening XPC`() async throws {
            let delays = Mutex<[Duration]>([])
            let interrupted = AsyncStream<Void>.makeStream()
            let clock = XPCClock(now: { 0 }, sleep: { delay in delays.withLock { $0.append(delay) } })
            let transport = NSXPCClientTransport(clock: clock, requestSender: { _, _, _ in })
            try await transport.connect(callbacks: .init(invalidated: { interrupted.continuation.yield(()) }))
            await #expect(throws: DaemonError.disconnected) { try await transport.send(Envelope(body: .status).encoded(), secrets: nil) }
            var invalidations = interrupted.stream.makeAsyncIterator()
            #expect(await invalidations.next() != nil)
            #expect(delays.withLock { $0 } == [.seconds(5)])
            await transport.invalidate()
        }
    #endif
}
