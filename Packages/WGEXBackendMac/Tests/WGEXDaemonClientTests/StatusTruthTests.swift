// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct StatusTruthTests {
    @Test
    func `launch and cached replies cannot manufacture a measurement`() async throws {
        let transport = ScriptedStatusTransport()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        var stream = client.statusUpdates().makeAsyncIterator()
        let seed = try #require(await stream.next())
        #expect(seed.protection == .unknown)
        #expect(seed.measuredAt == nil)
        _ = try await client.connect()
        let original = try #require(await stream.next())
        try await client.refreshStatus()
        #expect(await stream.next() == original)
        #expect(await transport.requests.filter { $0 == .status }.count == 2)
        await client.disconnect()
    }

    @Test
    func `connected heartbeat gap becomes not reporting without waiting for a request`() async throws {
        let time = Mutex<TimeInterval>(100)
        let transport = ScriptedStatusTransport(measuredAtContinuous: 100)
        let client = DaemonClient(
            transport: transport, clientVersion: "1", clientBuild: 10,
            clock: XPCClock(now: { time.withLock { $0 } }, sleep: { try await ContinuousClock().sleep(for: $0) }),
        )
        _ = try await client.connect()
        time.withLock { $0 = 116 }
        await client.evaluateStaleness()
        var stream = client.statusUpdates().makeAsyncIterator()
        let gap = try #require(await stream.next())
        #expect(gap.protection == .unknown)
        #expect(gap.notReportingSince == transport.measurementDate)
        #expect(gap.measuredAt == nil)
        await client.disconnect()
    }

    @Test
    func `a reused sequence cannot renew cached measurement time`() async throws {
        let time = Mutex<TimeInterval>(100)
        let transport = ScriptedStatusTransport(measuredAtContinuous: 100)
        let client = DaemonClient(
            transport: transport,
            clientVersion: "1",
            clientBuild: 10,
            clock: .init(now: { time.withLock { $0 } }, sleep: { try await ContinuousClock().sleep(for: $0) }),
        )
        _ = try await client.connect()
        time.withLock { $0 = 116 }
        await transport.changeCachedMeasurementTime(116)
        try await client.refreshStatus()
        var updates = client.statusUpdates().makeAsyncIterator()
        let status = try #require(await updates.next())
        #expect(status.protection == .unknown)
        #expect(status.measuredAt == nil)
        #expect(status.notReportingSince == transport.measurementDate)
        await client.disconnect()
    }

    @Test
    func `stop while hello is pending prevents the later start request`() async throws {
        let transport = ScriptedStatusTransport()
        await transport.pauseHello()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        let start = Task { try await client.start(UUID(), transport: nil) }
        while await !transport.helloPending {
            await Task.yield()
        }
        let originalIntent = await client.pendingIntent
        let stop = Task { try await client.stopCurrent() }
        // Wait for admission, not elapsed wall time, before the transport releases hello.
        while await client.pendingIntent == originalIntent {
            await Task.yield()
        }
        await transport.releaseHello()
        try await stop.value
        do {
            try await start.value
            Issue.record("Cancelled start completed")
        } catch { #expect((error as? TunnelError) == .cancelled) }
        #expect(await !transport.requests.contains { $0.kind == .startIntent })
        await client.disconnect()
    }

    @Test
    func `subscription loss resubscribes before requesting measured status`() async throws {
        let transport = ScriptedStatusTransport()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        _ = try await client.connect()
        await transport.emit(.subscriptionLost)
        for _ in 0 ..< 1000 {
            if await transport.requests.count >= 5 {
                break
            }
            await Task.yield()
        }
        #expect(await transport.requests.suffix(2) == [.subscribeEvents(includeLogs: false), .status])
        await client.disconnect()
    }

    @Test
    func `newer daemon refuses older client before subscription`() async throws {
        let transport = ScriptedStatusTransport(daemonBuild: 11)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        await #expect(throws: DaemonError.downgradeDetected) { try await client.connect() }
        #expect(await transport.requests == [.hello(clientVersion: "1", clientBuild: 10)])
    }

    @Test
    func `request timeout interrupts then reconnects with backoff and pauses while hidden`() async throws {
        let clock = AdvancingClock()
        let transport = ScriptedStatusTransport(measuredAtContinuous: 0)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, clock: clock.clock, jitter: { 1 })
        _ = try await client.connect()
        await client.setSurfaceVisible(false)
        await transport.dropNextStatus()
        await #expect(throws: DaemonError.disconnected) { try await client.refreshStatus() }
        #expect(clock.delays.isEmpty)
        var connections = await client.connectionStates().makeAsyncIterator()
        #expect(await connections.next() == .disconnected(lastError: .unavailable))
        await client.setSurfaceVisible(true)
        for _ in 0 ..< 1000 {
            if await transport.requests.filter({ $0.kind == .hello }).count == 2 {
                break
            }
            await Task.yield()
        }
        #expect(clock.delays == [.seconds(1)])
        await client.disconnect()
    }
}

/// Scriptable in-memory transport; never opens a Mach service or accesses secrets.
package actor ScriptedStatusTransport: XPCTransport {
    package nonisolated let measurementDate = Date(timeIntervalSince1970: 1000)
    private var instanceID = UUID()
    package func restartInstance() {
        instanceID = UUID()
    }

    private let daemonBuild: Int
    private var measuredAtContinuous: TimeInterval
    private var callbacks: XPCClientCallbacks?
    package private(set) var requests: [Request] = []
    package private(set) var preparationHadGrant = false
    package var failPreparation = false
    package func failUpdatePreparation() {
        failPreparation = true
    }

    private var pausedHello = false
    private var helloGate: CheckedContinuation<Void, Never>?
    package var helloPending: Bool {
        helloGate != nil
    }

    package func pauseHello() {
        pausedHello = true
    }

    package func releaseHello() {
        helloGate?.resume(); helloGate = nil
    }

    package var dropStatus = false
    package var statusDelay: Duration = .zero

    package init(daemonBuild: Int = 10, measuredAtContinuous: TimeInterval = XPCClock.continuousSeconds) {
        self.daemonBuild = daemonBuild
        self.measuredAtContinuous = measuredAtContinuous
    }

    package func connect(callbacks: XPCClientCallbacks) {
        self.callbacks = callbacks
    }

    package func invalidate() {
        callbacks = nil
    }

    package func changeCachedMeasurementTime(_ value: TimeInterval) {
        measuredAtContinuous = value
    }

    package func dropNextStatus() {
        dropStatus = true
    }

    package func emit(_ event: Event) async {
        if let bytes = try? WireCodec.encode(event) {
            await callbacks?.event(bytes)
        }
    }

    package func send(_ envelope: Data, secrets _: Data?) async throws -> Data {
        let decoded = try Envelope.decode(envelope)
        let request = decoded.body
        requests.append(request)
        let reply: Reply
        switch request {
        case .prepareForUpdate:
            preparationHadGrant = decoded.authorization == Data([1])
            reply = failPreparation ? .error(.notAuthorised(.adminRightRequired)) : .ok
        case .hello:
            if pausedHello {
                await withCheckedContinuation { helloGate = $0 }
            }
            reply = .hello(.init(
                daemonVersion: "1",
                daemonBuild: daemonBuild,
                protocolVersion: Envelope.currentProtocolVersion,
                minimumClientBuild: 1, instanceID: instanceID,
            ))
        case .status:
            if dropStatus {
                dropStatus = false
                return try await RequestDeadline(clock: .init(now: { 0 }, sleep: { _ in })).wait(
                    for: .status, begin: { _ in }, interrupted: { [callbacks] in await callbacks?.invalidated() },
                )
            }
            if statusDelay != .zero {
                try await ContinuousClock().sleep(for: statusDelay)
            }
            var status = TunnelStatus.idle
            status.sequence = 1
            status.measuredAt = measurementDate
            status.measuredAtContinuous = measuredAtContinuous
            reply = .status(status)
        default: reply = .ok
        }
        return try WireCodec.encode(reply)
    }
}
