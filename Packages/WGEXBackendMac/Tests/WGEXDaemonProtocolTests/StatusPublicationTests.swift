// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct StatusPublicationTests {
    @Test(arguments: [
        Request.performSecureInstall, .installProfile(.init(profile: TunnelProfile(name: "Fixture"), revision: 1)),
        .installProfileCAS(TunnelProfile(name: "CAS"), expectedRevision: nil), .prepareForUpdate,
    ])
    func `production measurements include dispatcher operations in replies and heartbeats`(_ request: Request) async throws {
        let service = DispatcherService()
        await service.setWaiting(for: request.kind)
        let next = Mutex<UInt64>(0)
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 9,
            minimumClientBuild: 1,
            authorisation: .init(
                isConsoleUser: { _ in true },
                hasAdminRight: { form, _ in form == Data([1]) },
            ),
            measureStatus: {
                var status = TunnelStatus.idle
                status.sequence = next.withLock { $0 += 1; return $0 }
                status.measuredAt = Date(); status.measuredAtContinuous = XPCClock.continuousSeconds
                return .init(status: status, ownerUID: 501)
            },
        )
        let delivered = AsyncStream<Event>.makeStream()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: { bytes in
            if let event = try? WireCodec.decode(Event.self, from: bytes) {
                delivered.continuation.yield(event)
            }
        }))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        let mutation = Task {
            try await transport.send(Envelope(authorization: Data([1]), body: request).encoded(), secrets: nil)
        }
        while await service.waiting == nil {
            await Task.yield()
        }
        guard case let .status(reply) = try await call(transport, .status) else { Issue.record("Missing status"); return }
        #expect(reply.operationInFlight)
        await dispatcher.heartbeat()
        var events = delivered.stream.makeAsyncIterator()
        guard case let .status(heartbeat) = await events.next() else { Issue.record("Missing heartbeat"); return }
        #expect(heartbeat.operationInFlight)
        await service.release()
        _ = try await mutation.value
        guard case let .status(after) = try await call(transport, .status) else { Issue.record("Missing final status"); return }
        #expect(!after.operationInFlight)
        await transport.invalidate()
    }

    @Test
    func `additive protocol reads do not count as mutations`() async throws {
        for revision in [false, true] {
            let service = DispatcherService()
            await service.setWaiting(for: revision ? .installProfile : .status)
            let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
            let transport = try await handshaken(dispatcher)
            let request: Request = revision ? .profileRevision(service.profile) : .protectionReasons
            let pending = Task { try await call(transport, request) }
            while await service.waiting == nil {
                await Task.yield()
            }
            #expect(await dispatcher.operationsInFlight == 0)
            await service.release()
            _ = try await pending.value
            await transport.invalidate()
        }
    }

    @Test
    func `heartbeat keeps publishing while start is suspended and recovery is pending`() async throws {
        let service = DispatcherService()
        await service.setWaiting()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let delivered = AsyncStream<Event>.makeStream()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: {
            if let event = try? WireCodec.decode(Event.self, from: $0) {
                delivered.continuation.yield(event)
            }
        }))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        let start = Task { try await call(transport, .startIntent(profileID: service.profile, transport: nil, hasSecrets: false)) }
        while await service.waiting == nil {
            await Task.yield()
        }
        await dispatcher.setRecovering(true)
        await dispatcher.heartbeat()
        var events = delivered.stream.makeAsyncIterator()
        guard case let .status(status) = await events.next() else { Issue.record("Missing heartbeat"); return }
        #expect(status.sequence > 0)
        #expect(status.measuredAt != nil)
        #expect(status.measuredAtContinuous != nil)
        #expect(status.operationInFlight)
        await service.release()
        _ = try await start.value
        await transport.invalidate()
    }

    @Test
    func `sequence allocator survives a dispatcher restart`() async throws {
        let persisted = Mutex<UInt64>(0)
        let allocate: @Sendable () throws -> UInt64 = { persisted.withLock { $0 += 1; return $0 } }
        func make() -> DaemonDispatcher {
            DaemonDispatcher(
                service: DispatcherService(),
                daemonVersion: "1",
                daemonBuild: 10,
                minimumClientBuild: 1,
                nextStatusSequence: allocate,
            )
        }
        let first = try await handshaken(make())
        guard case let .status(before) = try await call(first, .status) else { Issue.record("No status"); return }
        await first.invalidate()
        let second = try await handshaken(make())
        guard case let .status(after) = try await call(second, .status) else { Issue.record("No status"); return }
        #expect(after.sequence > before.sequence)
        await second.invalidate()
    }

    @Test
    func `concurrent status publications arrive in monotonically increasing order`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let delivered = AsyncStream<TunnelStatus>.makeStream()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: { bytes in
            if case let .status(status) = try? WireCodec.decode(Event.self, from: bytes) {
                delivered.continuation.yield(status)
            }
        }))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 20 {
                group.addTask { await dispatcher.publish(.status(.idle), profileID: service.profile) }
            }
        }
        var events = delivered.stream.makeAsyncIterator()
        var sequences: [UInt64] = []
        for _ in 0 ..< 20 {
            let status = try #require(await events.next())
            sequences.append(status.sequence)
        }
        #expect(sequences == sequences.sorted())
        #expect(Set(sequences).count == 20)
        await transport.invalidate()
    }

    @Test
    func `a measured status keeps its profile and times when current intent changes`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let delivered = AsyncStream<Event>.makeStream()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: { bytes in
            if let event = try? WireCodec.decode(Event.self, from: bytes) {
                delivered.continuation.yield(event)
            }
        }))
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        var measured = TunnelStatus.idle
        measured.phase = .active(Generation(rawValue: 9))
        measured.protection = .protected
        measured.activeProfileID = service.otherProfile
        measured.measuredAt = Date(timeIntervalSince1970: 1000)
        measured.measuredAtContinuous = 100
        await dispatcher.publish(.status(measured), profileID: measured.activeProfileID, ownerUID: 501)
        var updates = delivered.stream.makeAsyncIterator()
        guard case let .status(status) = await updates.next() else { Issue.record("No status"); return }
        #expect(status.activeProfileID == measured.activeProfileID)
        #expect(status.measuredAt == measured.measuredAt)
        #expect(status.measuredAtContinuous == measured.measuredAtContinuous)
        await transport.invalidate()
    }

    @Test
    func `status uses the atomic measurement and rechecks its owner after authorisation`() async throws {
        let service = DispatcherService()
        var status = TunnelStatus.idle
        status.activeProfileID = service.otherProfile
        status.measuredAt = Date(timeIntervalSince1970: 1000)
        status.measuredAtContinuous = 100
        let measurement = StatusMeasurement(status: status, ownerUID: 502)
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            measureStatus: { measurement },
        )
        let transport = try await handshaken(dispatcher)
        #expect(try await call(transport, .status) == .error(.notAuthorised(.notOwner)))
        await transport.invalidate()
    }
}
