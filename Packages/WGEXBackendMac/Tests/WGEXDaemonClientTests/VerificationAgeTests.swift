// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerificationAgeTests {
    @Test
    func `new daemon instance accepts a lower sequence without losing interruption history`() async throws {
        let transport = ScriptedStatusTransport()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        _ = try await client.connect()
        var high = TunnelStatus.idle
        high.phase = .active(.init(rawValue: 33)); high.protection = .protected
        high.sequence = 100
        high.measuredAt = Date(); high.measuredAtContinuous = XPCClock.continuousSeconds
        high.verifiedAt = high.measuredAt; high.verifiedAtContinuous = high.measuredAtContinuous
        await transport.emit(.status(high))
        while await client.sequenceFloor < 100 {
            await Task.yield()
        }
        await client.disconnect()
        var history = client.statusUpdates().makeAsyncIterator()
        #expect(await history.next()?.phase == high.phase)
        await transport.restartInstance()
        _ = try await client.connect()
        #expect(await client.sequenceFloor == 1)
        await client.disconnect()
    }

    @Test(arguments: [(TimeInterval(19), ProtectionState.protected), (20, .unknown), (21, .unknown)], [false, true])
    func `a heartbeat cannot renew settled policy verification and unknown retains measured history`(
        _ evidence: (TimeInterval, ProtectionState), _ operation: Bool,
    ) async throws {
        let (age, expectedProtection) = evidence
        let time = Mutex<TimeInterval>(100)
        let transport = ScriptedStatusTransport(measuredAtContinuous: 100)
        let client = DaemonClient(
            transport: transport,
            clientVersion: "1",
            clientBuild: 10,
            clock: .init(now: { time.withLock { $0 } }, sleep: { try await ContinuousClock().sleep(for: $0) }),
        )
        _ = try await client.connect()
        var status = TunnelStatus.idle
        status.phase = .active(.init(rawValue: 33)); status.protection = .protected
        status.policyEnforcing = true
        status.operationInFlight = operation
        status.record(.init(date: Date(timeIntervalSince1970: 1000), kind: .phaseChanged, generation: .init(rawValue: 33)))
        status.sequence = 2; status.measuredAt = Date(timeIntervalSince1970: 1000 + age); status.measuredAtContinuous = 100 + age
        status.verifiedAt = Date(timeIntervalSince1970: 1000); status.verifiedAtContinuous = 100
        time.withLock { $0 = 100 + age }
        await transport.emit(.status(status))
        while await client.sequenceFloor < 2 {
            await Task.yield()
        }
        var updates = client.statusUpdates().makeAsyncIterator()
        let gap = try #require(await updates.next())
        #expect(gap.protection == expectedProtection)
        #expect(gap.phase == status.phase)
        #expect(gap.recentEvents == status.recentEvents)
        #expect(gap.serviceResponding)
        #expect(gap.verificationExpired == (expectedProtection == .unknown))
        #expect((gap.measuredAt == nil) == (expectedProtection == .unknown))
        await client.disconnect()
    }

    @Test(arguments: [ProtectionState.unprotected, .unsupported, .unknown])
    func `heartbeat alone keeps non PF claims fresh without verification`(_ protection: ProtectionState) async throws {
        let transport = ScriptedStatusTransport(measuredAtContinuous: 120)
        let client = DaemonClient(
            transport: transport,
            clientVersion: "1",
            clientBuild: 10,
            clock: .init(now: { 120 }, sleep: { try await ContinuousClock().sleep(for: $0) }),
        )
        _ = try await client.connect()
        var status = TunnelStatus.idle
        status.protection = protection; status.sequence = 2
        status.measuredAt = Date(); status.measuredAtContinuous = 120
        await transport.emit(.status(status))
        while await client.sequenceFloor < 2 {
            await Task.yield()
        }
        var updates = client.statusUpdates().makeAsyncIterator()
        let current = try #require(await updates.next())
        #expect(current.protection == protection)
        #expect(!current.verificationExpired)
        #expect(current.measuredAt != nil)
        await client.disconnect()
    }

    @Test(arguments: [false, true])
    func `an in flight operation or a non enforcing policy does not age out the known phase`(_ operation: Bool) async throws {
        let transport = ScriptedStatusTransport(measuredAtContinuous: 130)
        let client = DaemonClient(
            transport: transport,
            clientVersion: "1",
            clientBuild: 10,
            clock: .init(now: { 130 }, sleep: { try await ContinuousClock().sleep(for: $0) }),
        )
        _ = try await client.connect()
        var status = TunnelStatus.idle
        status.phase = .preparing(.init(rawValue: 7)); status.protection = .blocked
        status.operationInFlight = operation; status.policyEnforcing = operation
        status.sequence = 2; status.measuredAt = Date(); status.measuredAtContinuous = 130
        status.verifiedAt = Date(timeIntervalSince1970: 1000); status.verifiedAtContinuous = 100
        await transport.emit(.status(status))
        while await client.sequenceFloor < 2 {
            await Task.yield()
        }
        var updates = client.statusUpdates().makeAsyncIterator()
        let current = try #require(await updates.next())
        #expect(current.phase == status.phase)
        #expect(current.protection == .blocked)
        #expect(!current.verificationExpired)
        await client.disconnect()
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct LostStartAcknowledgementTests {
    @Test
    func `cancel fences the acknowledged generation after current stop raced ahead`() async throws {
        let transport = LateStartTransport()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        let profile = UUID()
        let start = Task { try await client.start(profile, transport: nil) }
        while await !transport.pending {
            await Task.yield()
        }
        try await client.stopCurrent()
        await transport.release()
        await #expect(throws: TunnelError.cancelled) { try await start.value }
        let last = try #require(await transport.envelopes.last)
        #expect(last.body == .stop(profileID: profile, reason: .userRequested))
        #expect(last.expectedGeneration == .init(rawValue: 77))
        await client.disconnect()
    }
}

private actor LateStartTransport: XPCTransport {
    private var start: CheckedContinuation<Data, any Error>?
    private(set) var envelopes: [Envelope] = []
    var pending: Bool {
        start != nil
    }

    func connect(callbacks _: XPCClientCallbacks) {}
    func invalidate() {}
    func release() {
        start?.resume(returning: (try? WireCodec.encode(Reply.started(.init(rawValue: 77)))) ?? Data())
        start = nil
    }

    func send(_ bytes: Data, secrets _: Data?) async throws -> Data {
        let envelope = try Envelope.decode(bytes); envelopes.append(envelope)
        let reply: Reply
        switch envelope.body {
        case .hello: reply = .hello(.init(
                daemonVersion: "1",
                daemonBuild: 10,
                protocolVersion: Envelope.currentProtocolVersion,
                minimumClientBuild: 1,
            ))
        case .status: reply = .status(.idle)
        case .startIntent: return try await withCheckedThrowingContinuation { start = $0 }
        default: reply = .ok
        }
        return try WireCodec.encode(reply)
    }
}
