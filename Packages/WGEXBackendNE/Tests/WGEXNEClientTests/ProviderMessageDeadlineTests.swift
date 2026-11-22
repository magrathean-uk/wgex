// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
@testable import WGEXNEClient

private enum Mode: Sendable {
    case hold, reply(Data), fail
}

/// A system whose `sendProviderMessage` is driven by the test. A held send ignores cancellation on purpose, like a real
/// session that never calls its handler, so a deadline that waited for it would hang the caller.
private actor ScriptedSystem: VPNManagerSystem {
    private var stored: [VPNManagerRecord] = []
    private var held: [CheckedContinuation<Data, any Error>] = []
    private let mode: Mode
    private let events = AsyncStream<VPNStatusEvent>.makeStream()
    private let heldSignal = AsyncStream<Void>.makeStream()
    private let returnedSignal = AsyncStream<Void>.makeStream()

    init(mode: Mode) {
        self.mode = mode
    }

    func loadAll() -> [VPNManagerRecord] {
        stored
    }

    func save(_ record: VPNManagerRecord) {
        stored.removeAll { $0.configuration.profileID == record.configuration.profileID }; stored.append(record)
    }

    func remove(_: UUID) {}
    func start(_: UUID, transport _: UUID?) {}
    func stop(_: UUID) {}
    func startConfirmed(_: UUID, revision _: String?) {}
    func statusEvents() -> AsyncStream<VPNStatusEvent> {
        events.stream
    }

    func sendProviderMessage(_: UUID, data _: Data) async throws -> Data {
        defer { returnedSignal.continuation.yield() }
        switch mode {
        case .hold:
            return try await withCheckedThrowingContinuation { continuation in
                held.append(continuation); heldSignal.continuation.yield()
            }
        case let .reply(data): return data
        case .fail: throw TunnelError.backendUnavailable
        }
    }

    /// Suspends until one send is parked.
    func waitUntilHeld() async {
        var iterator = heldSignal.stream.makeAsyncIterator()
        _ = await iterator.next()
    }

    /// Suspends until one send has returned to its caller (reply delivered or thrown).
    func waitUntilReturned() async {
        var iterator = returnedSignal.stream.makeAsyncIterator()
        _ = await iterator.next()
    }

    func releaseHeld(with data: Data) {
        let all = held; held = []
        for continuation in all {
            continuation.resume(returning: data)
        }
    }
}

/// Records the requested deadline and whether the timer was cancelled. The timer never fires unless `fire` is set.
private actor TimerProbe {
    private(set) var requested: [Duration] = []
    private let cancelled = AsyncStream<Void>.makeStream()

    func begin(_ duration: Duration) {
        requested.append(duration)
    }

    func cancelledByCaller() {
        cancelled.continuation.yield()
    }

    func waitUntilCancelled() async {
        var iterator = cancelled.stream.makeAsyncIterator()
        _ = await iterator.next()
    }
}

/// Never completes by itself: it ends only when its task is cancelled. No clock is involved.
private func idleTimer(_ probe: TimerProbe) -> @Sendable (Duration) async throws -> Void {
    { duration in
        await probe.begin(duration)
        for await _ in AsyncStream<Void>.makeStream().stream {}
        await probe.cancelledByCaller()
        throw CancellationError()
    }
}

/// Fires at once, as if the deadline had already passed.
private let expiredTimer: @Sendable (Duration) async throws -> Void = { _ in }

private func statisticsReply() throws -> Data {
    try ProviderCodec.encode(ProviderReply.statistics(TunnelStatistics(
        generation: 7, sampledAt: Date(timeIntervalSince1970: 0), interfaceName: "utun-test", listenPort: nil, peers: [],
    )))
}

private func startedClient(
    _ system: ScriptedSystem, sleep: @escaping @Sendable (Duration) async throws -> Void,
) async throws -> NEManagerClient {
    let profile = try GoldenFixture.profile()
    let client = NEManagerClient(system: system, platform: .iOS, sleep: sleep)
    try await client.install(profile)
    try await client.start(profile.id, transport: nil)
    return client
}

@Suite(.timeLimit(.minutes(1)))
private struct ProviderMessageDeadlineTests {
    @Test
    func `a reply that never arrives fails with timedOut after the ten second deadline`() async throws {
        let probe = TimerProbe()
        let system = ScriptedSystem(mode: .hold)
        let client = try await startedClient(system) { duration in
            await probe.begin(duration)
        }
        await #expect(throws: TunnelError.timedOut) { try await client.statistics() }
        #expect(await probe.requested == [.seconds(10)])
        await system.waitUntilHeld()
        await system.releaseHeld(with: Data())
        await client.shutdown()
    }

    @Test
    func `a late reply after the deadline is dropped without a second delivery`() async throws {
        let system = ScriptedSystem(mode: .hold)
        let client = try await startedClient(system, sleep: expiredTimer)
        await #expect(throws: TunnelError.timedOut) { try await client.statistics() }
        await system.waitUntilHeld()
        // The parked send now returns a valid reply into a gate that already delivered the timeout.
        let late = try statisticsReply()
        await system.releaseHeld(with: late)
        await system.waitUntilReturned()
        // A second statistics call opens a fresh gate and is unaffected by the dropped reply.
        await #expect(throws: TunnelError.timedOut) { try await client.statistics() }
        await system.waitUntilHeld()
        await system.releaseHeld(with: late)
        await client.shutdown()
    }

    @Test
    func `a reply inside the deadline is delivered and the timer is cancelled`() async throws {
        let probe = TimerProbe()
        let system = try ScriptedSystem(mode: .reply(statisticsReply()))
        let client = try await startedClient(system, sleep: idleTimer(probe))
        #expect(try await client.statistics().generation == 7)
        await probe.waitUntilCancelled()
        await client.shutdown()
    }

    @Test
    func `a throwing send surfaces its error and cancels the timer`() async throws {
        let probe = TimerProbe()
        let system = ScriptedSystem(mode: .fail)
        let client = try await startedClient(system, sleep: idleTimer(probe))
        await #expect(throws: TunnelError.backendUnavailable) { try await client.statistics() }
        await probe.waitUntilCancelled()
        await client.shutdown()
    }

    @Test
    func `cancelling the caller while the reply is outstanding throws cancelled once`() async throws {
        let probe = TimerProbe()
        let system = ScriptedSystem(mode: .hold)
        let client = try await startedClient(system, sleep: idleTimer(probe))
        let call = Task { try await client.statistics() }
        await system.waitUntilHeld()
        call.cancel()
        await #expect(throws: TunnelError.cancelled) { try await call.value }
        await probe.waitUntilCancelled()
        await system.releaseHeld(with: Data())
        await client.shutdown()
    }

    @Test
    func `the single resume gate delivers the first outcome and drops the rest`() async throws {
        let gate = SingleResume<Int>()
        let value = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, any Error>) in
            gate.install(continuation)
            #expect(gate.finish(.success(1)))
            #expect(!gate.finish(.success(2)))
            #expect(!gate.finish(.failure(TunnelError.timedOut)))
        }
        #expect(value == 1)
    }

    @Test
    func `an outcome that arrives before installation is replayed once`() async throws {
        let gate = SingleResume<Int>()
        #expect(gate.finish(.failure(CancellationError())))
        await #expect(throws: CancellationError.self) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, any Error>) in
                gate.install(continuation)
            }
        }
        #expect(!gate.finish(.success(3)))
    }

    @Test
    func `nil and oversize replies are configuration errors and a sized reply passes`() {
        #expect(throws: (any Error).self) { try providerReplyOutcome(nil).get() }
        let oversize = Data(count: ProviderCodec.maximumBytes + 1)
        #expect(throws: (any Error).self) { try providerReplyOutcome(oversize).get() }
        let exact = Data(count: ProviderCodec.maximumBytes)
        #expect((try? providerReplyOutcome(exact).get()) == exact)
    }
}
