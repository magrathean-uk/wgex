// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct RequestDeadlineTests {
    @Test
    func `deadlines cover default hello and mutating long requests`() {
        #expect(RequestDeadline.duration(for: .status) == .seconds(5))
        #expect(RequestDeadline.duration(for: .hello(clientVersion: "1", clientBuild: 10)) == .seconds(10))
        #expect(RequestDeadline.duration(for: .startIntent(profileID: UUID(), transport: nil, hasSecrets: false)) == .seconds(30))
        #expect(RequestDeadline.duration(for: .stopCurrent(reason: .userRequested)) == .seconds(30))
        #expect(RequestDeadline.duration(for: .performSecureInstall) == .seconds(30))
        #expect(RequestDeadline.duration(for: .armOnDemand(profileID: UUID(), hasSecrets: false)) == .seconds(30))
        #expect(RequestDeadline.duration(for: .disarmOnDemand(profileID: UUID())) == .seconds(30))
        #expect(RequestDeadline.duration(for: .stop(profileID: UUID(), reason: .userRequested)) == .seconds(30))
    }

    @Test(.timeLimit(.minutes(1)))
    func `a disarm or arm behind a slow stop is not timed out`() async throws {
        for request in [Request.disarmOnDemand(profileID: UUID()), .armOnDemand(profileID: UUID(), hasSecrets: false)] {
            let clock = ManualDeadlineClock()
            let deadline = RequestDeadline(clock: clock.xpc)
            let reply = Mutex<(@Sendable (Result<Data, any Error>) -> Void)?>(nil)
            let task = Task {
                try await deadline.wait(
                    for: request, begin: { callback in reply.withLock { $0 = callback } }, interrupted: {},
                )
            }
            var registered = clock.registrations.makeAsyncIterator()
            _ = await registered.next()
            // A stop holding the serial control lane for 20 s would have timed out the old 5 s budget.
            clock.advance(by: .seconds(20))
            reply.withLock { $0 }?(.success(Data([7])))
            #expect(try await task.value == Data([7]))
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func `the same wait still times out past the budget`() async {
        let clock = ManualDeadlineClock()
        let deadline = RequestDeadline(clock: clock.xpc)
        let task = Task {
            try await deadline.wait(for: .disarmOnDemand(profileID: UUID()), begin: { _ in }, interrupted: {})
        }
        var registered = clock.registrations.makeAsyncIterator()
        _ = await registered.next()
        clock.advance(by: .seconds(29))
        clock.advance(by: .seconds(1))
        await #expect(throws: DaemonError.disconnected) { try await task.value }
    }

    @Test
    func `deadline releases an unanswered callback and reports interruption`() async {
        let expired = AsyncStream<Void>.makeStream()
        let deadline = RequestDeadline(clock: XPCClock(now: { 0 }, sleep: { _ in }))
        await #expect(throws: DaemonError.disconnected) {
            try await deadline.wait(for: .status, begin: { _ in }, interrupted: { expired.continuation.yield(()) })
        }
        var events = expired.stream.makeAsyncIterator()
        #expect(await events.next() != nil)
    }
}

/// A clock whose sleepers wake only when the test advances virtual time.
private final class ManualDeadlineClock: Sendable {
    private struct Sleeper { let due: TimeInterval; let continuation: CheckedContinuation<Void, any Error> }
    private struct State { var now: TimeInterval = 0; var sleepers: [UUID: Sleeper] = [:] }
    private let state = Mutex(State())
    private let stream = AsyncStream<Void>.makeStream()

    /// One element for each sleeper registered.
    var registrations: AsyncStream<Void> {
        stream.stream
    }

    var xpc: XPCClock {
        XPCClock(now: { self.state.withLock { $0.now } }, sleep: { try await self.sleep($0) })
    }

    func advance(by duration: Duration) {
        let parts = duration.components
        let due = state.withLock { state -> [CheckedContinuation<Void, any Error>] in
            state.now += Double(parts.seconds) + Double(parts.attoseconds) / 1e18
            let expired = state.sleepers.filter { $0.value.due <= state.now }
            for key in expired.keys {
                state.sleepers[key] = nil
            }
            return expired.values.map(\.continuation)
        }
        for continuation in due {
            continuation.resume()
        }
    }

    private func sleep(_ duration: Duration) async throws {
        let id = UUID(), parts = duration.components
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let cancelled = state.withLock { state -> Bool in
                    guard !Task.isCancelled else { return true }
                    state.sleepers[id] = Sleeper(
                        due: state.now + Double(parts.seconds) + Double(parts.attoseconds) / 1e18, continuation: continuation,
                    )
                    return false
                }
                if cancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    stream.continuation.yield(())
                }
            }
        } onCancel: {
            let sleeper = state.withLock { $0.sleepers.removeValue(forKey: id) }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }
}
