// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct DaemonClientTests {
    @Test
    func `busy is preserved as a distinct client error`() {
        #expect(DaemonError.busy.tunnelError == .busy)
        #expect(DaemonError.tunnel(.revisionConflict).tunnelError == .revisionConflict)
    }

    @Test
    func `backend capabilities handshake status statistics and generation mapping`() async throws {
        let (service, dispatcher, transport, client) = clientFixture()
        #expect(client.capabilities.contains([.killSwitch, .lockdown, .captiveWindow, .startBeforeLogin, .allowLAN]))
        _ = try await client.connect()
        #expect(await transport.requests.prefix(3).map(\.kind) == [.hello, .subscribeEvents, .status])
        var updates = client.statusUpdates().makeAsyncIterator()
        let idle = try #require(await updates.next())
        assertFields(idle, expected: .idle)
        var active = TunnelStatus.idle
        active.phase = .active(Generation(rawValue: 77))
        active.protection = .protected
        active.verifiedAt = Date(); active.verifiedAtContinuous = XPCClock.continuousSeconds
        await dispatcher.publish(.status(active), profileID: service.id)
        let received = try #require(await updates.next())
        assertFields(received, expected: active)
        #expect(try await client.statistics().generation == 77)
        await #expect(throws: TunnelError.secretsUnavailable) { try await client.start(service.id, transport: nil) }
        try await client.stop(service.id)
        await client.disconnect()
    }

    @Test
    func `the log read uses the existing bounded logs request and returns the daemon's lines`() async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        let since = Date(timeIntervalSince1970: 1_800_000_000)
        let lines = [RedactedLogLine(date: since, category: "engine", message: "Interface up", profileID: nil)]
        await transport.override(.logs(lines), for: .logs)
        #expect(try await client.logs(since: since, limit: 5000) == lines)
        #expect(await transport.requests.last == .logs(since: since, limit: 512))
        #expect(try await client.logs(since: nil) == lines)
        #expect(await transport.requests.last == .logs(since: nil, limit: 512))
        await transport.override(.ok, for: .logs)
        await #expect(throws: DaemonError.malformedMessage) { try await client.logs(since: nil) }
        await client.disconnect()
    }

    @Test
    func `client rejects daemon floor and protocol before secrets`() async throws {
        let (_, _, transport, _) = clientFixture()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 11)
        await #expect(throws: DaemonError.downgradeDetected) { try await client.connect() }
        #expect(await !transport.secretsObserved)
        await transport.override(.hello(.init(
            daemonVersion: "1",
            daemonBuild: 10,
            protocolVersion: Envelope.currentProtocolVersion + 1,
            minimumClientBuild: 1,
        )))
        let future = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        await #expect(throws: DaemonError.unsupportedProtocolVersion(Envelope.currentProtocolVersion + 1)) { try await future.connect() }
        await client.disconnect()
        await future.disconnect()
    }

    @Test
    func `reconnect uses exponential backoff then resyncs immediately with fake time`() async throws {
        let clock = AdvancingClock()
        let (service, _, transport, client) = clientFixture(clock: clock.clock)
        _ = try await client.connect()
        var updates = client.statusUpdates().makeAsyncIterator()
        _ = await updates.next()
        var active = TunnelStatus.idle
        active.phase = .active(Generation(rawValue: 9))
        active.protection = .protected
        active.verifiedAt = Date(); active.verifiedAtContinuous = clock.elapsed
        await service.setStatus(active)
        var connections = await client.connectionStates().makeAsyncIterator()
        #expect(await connections.next() == .connected(daemonBuild: 10))
        await transport.failConnections(2)
        await transport.interrupt()
        let unknown = await updates.next()
        #expect(unknown?.protection == .unknown)
        let restored = try #require(await updates.next())
        assertFields(restored, expected: active)
        #expect(await connections.next() == .disconnected(lastError: .unavailable))
        for _ in 0 ..< 2 {
            #expect(await connections.next() == .connecting)
            #expect(await connections.next() == .disconnected(lastError: .unavailable))
        }
        #expect(await connections.next() == .connecting)
        #expect(await connections.next() == .connected(daemonBuild: 10))
        #expect(clock.delays == [.seconds(1), .seconds(2), .seconds(4)])
        #expect(clock.elapsed == 7)
        #expect(await transport.connectionAttempts == 4)
        #expect(await transport.requests.suffix(3).map(\.kind) == [.hello, .subscribeEvents, .status])
        await client.disconnect()
    }

    @Test
    func `install strips Keychain references and caches daemon revisions across clients`() async throws {
        let (service, dispatcher, transport, client) = clientFixture()
        var profile = TunnelProfile(id: service.id, name: "Fixture")
        profile.secrets.privateKey = .keychain(persistentRef: Data([1, 2, 3]))
        try await client.install(profile)
        try await client.install(profile)
        let second = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        profile.name = "Second client edit"
        try await second.install(profile)
        profile.name = "Stale client edit"
        await #expect(throws: TunnelError.revisionConflict) { try await client.install(profile) }
        // A rollback or repeated save cannot overwrite the winner until an explicit reload.
        await #expect(throws: TunnelError.revisionConflict) { try await client.install(profile) }
        #expect(await transport.requests.filter {
            if case .installProfileCAS = $0 {
                true
            } else {
                false
            }
        }.count == 3)
        #expect(await transport.requests.filter { $0 == .profileRevision(profile.id) }.count == 1)
        #expect(try await client.refreshRevision(profile.id) == 2)
        try await client.install(profile)
        #expect(await transport.requests.filter { $0 == .profileRevision(profile.id) }.count == 2)
        let expected = await transport.requests.compactMap { request -> UInt64?? in
            if case let .installProfileCAS(_, revision) = request {
                return .some(revision)
            }
            return nil
        }
        #expect(expected.count == 4)
        #expect(expected == [nil, 1, 1, 2])
        let leaked = await transport.requests.contains { request in
            if case let .installProfileCAS(profile, _) = request, case .keychain = profile.secrets.privateKey {
                return true
            }
            return false
        }
        #expect(!leaked)
        try await client.remove(service.id, purgeSecrets: true)
        await client.disconnect(); await second.disconnect()
    }
}

private func assertFields(_ actual: TunnelStatus, expected: TunnelStatus) {
    #expect(actual.phase == expected.phase)
    #expect(actual.protection == expected.protection)
    #expect(actual.transport == expected.transport)
    #expect(actual.health == expected.health)
    #expect(actual.recentEvents == expected.recentEvents)
    #expect(actual.recoveryFailureReason == expected.recoveryFailureReason)
    #expect(actual.activeProfileID == expected.activeProfileID)
    #expect(actual.operationInFlight == expected.operationInFlight)
    #expect(actual.sequence > 0)
    #expect(actual.measuredAt != nil)
    #expect(actual.measuredAtContinuous != nil)
    #expect(actual.verifiedAt == expected.verifiedAt)
    #expect(actual.verifiedAtContinuous == expected.verifiedAtContinuous)
    #expect(actual.policyEnforcing == expected.policyEnforcing)
}
