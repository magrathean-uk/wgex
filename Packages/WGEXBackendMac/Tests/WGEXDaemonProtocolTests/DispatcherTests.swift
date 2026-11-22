// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct DispatcherTests {
    @Test
    func `impostor rejected before decode or controller dispatch`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5)
        let transport = InMemoryXPCTransport(daemon: dispatcher, peer: testPeer(accepted: false))
        await #expect(throws: DaemonError.unauthorised) { try await transport.connect(callbacks: .init()) }
        #expect(await service.calls.isEmpty)
    }

    @Test
    func `hello gates requests and both build floors`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5)
        let transport = InMemoryXPCTransport(daemon: dispatcher, peer: testPeer())
        try await transport.connect(callbacks: .init())
        #expect(try await call(transport, .status) == .error(.handshakeRequired))
        #expect(try await call(transport, .hello(clientVersion: "old", clientBuild: 4)) == .error(.downgradeDetected))
        guard case .hello = try await call(transport, .hello(clientVersion: "1", clientBuild: 10)) else {
            Issue.record("Handshake failed"); return
        }
        #expect(try await call(transport, .status).isMeasuredIdle)
        let rolledBack = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 9,
            minimumClientBuild: 5,
            minimumDaemonBuild: 10,
        )
        let other = InMemoryXPCTransport(daemon: rolledBack, peer: testPeer())
        try await other.connect(callbacks: .init())
        #expect(try await call(other, .hello(clientVersion: "1", clientBuild: 10)) == .error(.downgradeDetected))
        var future = Envelope(body: .hello(clientVersion: "1", clientBuild: 10))
        future.protocolVersion = Envelope.currentProtocolVersion + 1
        let bytes = try await transport.send(WireCodec.encode(future), secrets: nil)
        #expect(try WireCodec.decode(Reply.self, from: bytes) == .error(.unsupportedProtocolVersion(Envelope.currentProtocolVersion + 1)))
    }

    @Test
    func `token bucket rejects sixty fifth request and keeps connection usable`() async throws {
        let time = Mutex<TimeInterval>(0)
        let clock = XPCClock(now: { time.withLock { $0 } }, sleep: { _ in })
        let dispatcher = DaemonDispatcher(
            service: DispatcherService(),
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            clock: clock,
        )
        let transport = try await handshaken(dispatcher)
        for _ in 0 ..< 63 {
            #expect(try await call(transport, .status).isMeasuredIdle)
        }
        #expect(try await call(transport, .status) == .error(.rateLimited))
        time.withLock { $0 = 1 }
        #expect(try await call(transport, .status).isMeasuredIdle)
    }

    @Test
    func `envelope payload and secrets bounds are enforced`() async throws {
        let dispatcher = DaemonDispatcher(service: DispatcherService(), daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let transport = try await handshaken(dispatcher)
        let over = Data(count: WireCodec.maximumMessageSize + 1)
        let reply = try await transport.send(over, secrets: nil)
        #expect(try WireCodec.decode(Reply.self, from: reply) == .error(.messageTooLarge(over.count)))
        let payload = Data(count: DaemonDispatcher.maximumPayloadSize + 1)
        #expect(try await call(transport, .startIntent(profileID: UUID(), transport: nil, hasSecrets: true), secrets: payload)
            == .error(.messageTooLarge(payload.count)))
        #expect(try await call(transport, .status, secrets: Data([1])) == .error(.malformedMessage))
        let oversized = Request.hello(
            clientVersion: String(repeating: "x", count: DaemonDispatcher.maximumPayloadSize + 1),
            clientBuild: 10,
        )
        guard case .error(.messageTooLarge) = try await call(transport, oversized) else { Issue.record("Payload accepted"); return }
    }

    @Test
    func `logs and diagnostic scopes stay within caller uid`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let transport = try await handshaken(dispatcher)
        guard case let .logs(lines) = try await call(transport, .logs(since: nil, limit: 100)) else { Issue.record("No logs"); return }
        #expect(lines.count == 2)
        #expect(!lines.contains { $0.profileID == service.otherProfile })
        _ = try await call(
            transport,
            .diagnostics(.init(includeLogs: true, since: nil, profileIDs: [service.profile, service.otherProfile])),
        )
        #expect(await service.contexts.last?.visibleProfileIDs == [service.profile])
        #expect(await service.calls.last == .diagnostics(.init(includeLogs: true, since: nil, profileIDs: [service.profile])))
        let other = try await handshaken(dispatcher, uid: 999)
        _ = try await call(other, .diagnostics(.init(includeLogs: true, since: nil, profileIDs: [])))
        #expect(await service.contexts.last?.visibleProfileIDs == [])
        #expect(try await call(other, .status) == .error(.notAuthorised(.notOwner)))
    }

    @Test
    func `subscription count and uid log filtering`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let delivered = Mutex<[Event]>([])
        let callbacks = XPCClientCallbacks(event: { data in
            if let event = try? WireCodec.decode(Event.self, from: data) {
                delivered.withLock { $0.append(event) }
            }
        })
        let first = try await handshaken(dispatcher, callbacks: callbacks)
        #expect(try await call(first, .subscribeEvents(includeLogs: true)) == .ok)
        var retained: [InMemoryXPCTransport] = []
        for _ in 1 ..< 16 {
            let next = try await handshaken(dispatcher)
            #expect(try await call(next, .subscribeEvents(includeLogs: false)) == .ok)
            retained.append(next)
        }
        let excess = try await handshaken(dispatcher)
        #expect(try await call(excess, .subscribeEvents(includeLogs: true)) == .error(.subscriptionLimit))
        await dispatcher.publish(
            .log(.init(date: Date(), category: "test", message: "other", profileID: service.otherProfile)),
            profileID: nil,
        )
        await dispatcher.publish(.log(.init(date: Date(), category: "test", message: "own", profileID: service.profile)), profileID: nil)
        for _ in 0 ..< 100 where delivered.withLock({ $0.isEmpty }) {
            await Task.yield()
        }
        #expect(delivered.withLock { $0.count } == 1)
        await first.invalidate()
        #expect(try await call(excess, .subscribeEvents(includeLogs: true)) == .ok)
        #expect(retained.count == 15)
    }

    @Test
    func `overlapping stop reaches the service while start suspends`() async throws {
        let service = DispatcherService()
        await service.setWaiting()
        let policy = DaemonAuthorisation(isConsoleUser: { _ in true })
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: policy,
        )
        let transport = try await handshaken(dispatcher)
        let first = Task { try await call(transport, .startIntent(profileID: service.profile, transport: nil, hasSecrets: false)) }
        while await service.waiting == nil {
            await Task.yield()
        }
        #expect(try await call(transport, .stop(profileID: service.profile, reason: .userRequested)) == .ok)
        await service.release()
        #expect(try await first.value == .started(Generation(rawValue: 42)))
    }
}
