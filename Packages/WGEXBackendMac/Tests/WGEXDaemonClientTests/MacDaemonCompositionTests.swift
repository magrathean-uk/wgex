// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol
import WGEXProfileStore

@Suite(.timeLimit(.minutes(1)))
private struct MacDaemonCompositionTests {
    private func composition(_ transport: any XPCTransport, permitted: Bool = true) -> MacDaemonComposition {
        MacDaemonComposition(
            transport: transport, clientVersion: "1.0", clientBuild: 10,
            secretStore: InMemorySecretStore(), systemOperationsPermitted: permitted,
        )
    }

    @Test
    func `app composition connects once replays hello and propagates status`() async throws {
        let (service, dispatcher, transport, _) = clientFixture()
        let app = composition(transport)
        var connections = await app.client.connectionStates().makeAsyncIterator()
        #expect(await connections.next() == .disconnected(lastError: nil))
        try await app.start(profiles: [])
        #expect(await connections.next() == .connecting)
        #expect(await connections.next() == .connected(daemonBuild: 10))
        #expect(try await app.refreshDaemon())
        #expect(await transport.connectionAttempts == 1)
        #expect(await transport.requests.prefix(3) == [
            .hello(clientVersion: "1.0", clientBuild: 10),
            .subscribeEvents(includeLogs: false),
            .status,
        ])
        var late = await app.client.connectionStates().makeAsyncIterator()
        #expect(await late.next() == .connected(daemonBuild: 10))
        var updates = app.client.statusUpdates().makeAsyncIterator()
        #expect(await updates.next()?.phase == .idle)
        var status = TunnelStatus.idle
        status.phase = .active(Generation(rawValue: 37))
        status.protection = .protected
        await dispatcher.publish(.status(status), profileID: service.id)
        #expect(await updates.next()?.phase == status.phase)
        #expect(try await app.secureInstall() == .verified)
        #expect(await transport.requests.count == 4)
        await app.client.disconnect()
        #expect(await connections.next() == .disconnected(lastError: nil))
    }

    @Test
    func `host guard refuses launch refresh settings and captive operations before XPC`() async throws {
        let (_, _, transport, _) = clientFixture()
        let app = composition(transport, permitted: false)
        await #expect(throws: ServiceError.hostGuard) { try await app.start(profiles: []) }
        await #expect(throws: ServiceError.hostGuard) { try await app.refreshDaemon() }
        await #expect(throws: ServiceError.hostGuard) { try await app.secureInstall() }
        await #expect(throws: ServiceError.hostGuard) { try await app.saveStartup(TunnelProfile(name: "Fixture"), options: .init()) }
        await #expect(throws: ServiceError.hostGuard) { try await app.openCaptiveWindow(seconds: 60) }
        await #expect(throws: ServiceError.hostGuard) { try await app.closeCaptiveWindow() }
        #expect(await transport.connectionAttempts == 0)
        #expect(await transport.requests.isEmpty)
    }

    @Test
    func `connection failures are safe categories and refresh can retry`() async throws {
        let (_, _, transport, _) = clientFixture()
        let app = composition(transport)
        await transport.failConnections(1)
        var states = await app.client.connectionStates().makeAsyncIterator()
        _ = await states.next()
        await #expect(throws: DaemonError.disconnected) { try await app.refreshDaemon() }
        #expect(await states.next() == .connecting)
        #expect(await states.next() == .disconnected(lastError: .unavailable))
        #expect(try await app.refreshDaemon())
        #expect(await states.next() == .connecting)
        #expect(await states.next() == .connected(daemonBuild: 10))
        await app.client.disconnect()
    }

    @Test
    func `app build is independent of the compatibility floor`() async throws {
        let (_, _, transport, _) = clientFixture()
        let app = MacDaemonComposition(
            transport: transport, clientVersion: "1.1", clientBuild: 11,
            secretStore: InMemorySecretStore(), systemOperationsPermitted: true,
        )
        var states = await app.client.connectionStates().makeAsyncIterator()
        _ = await states.next()
        #expect(try await app.refreshDaemon())
        #expect(await states.next() == .connecting)
        #expect(await states.next() == .connected(daemonBuild: 10))
        #expect(await transport.requests.count == 3)
        await app.client.disconnect()
    }

    @Test
    func `startup registers store accounts sends separate secrets and captive requests are acknowledged`() async throws {
        let (service, _, transport, _) = clientFixture()
        let store = InMemorySecretStore()
        let account = SecretID(profileID: service.id, kind: .privateKey)
        var fixture = Data(repeating: 0xA5, count: 32)
        try await store.store(SecretBytes(wiping: &fixture), for: account)
        var profile = TunnelProfile(id: service.id, name: "Fixture")
        profile.secrets.privateKey = .daemonStore(id: account.id)
        let app = MacDaemonComposition(
            transport: transport, clientVersion: "1.0", clientBuild: 10,
            secretStore: store, systemOperationsPermitted: true,
        )
        try await app.start(profiles: [profile])
        // A CLI-initiated start can now ask the app for the imported account.
        var callback = try await transport.askForSecrets(profile.id)
        #expect(!callback.isEmpty)
        callback.resetBytes(in: 0 ..< callback.count)
        try await app.saveStartup(profile, options: .init(startBeforeLogin: true))
        #expect(await transport.secretsObserved)
        #expect(await transport.requests.contains(.setStartBeforeLoginIntent(profileID: profile.id, enabled: true)))
        try await app.saveStartup(profile, options: .init(autoConnectAtLogin: true))
        #expect(await transport.requests.contains(.setStartBeforeLoginIntent(profileID: profile.id, enabled: false)))
        try await app.openCaptiveWindow(seconds: 125)
        try await app.closeCaptiveWindow()
        #expect(await transport.requests.suffix(2) == [.openCaptiveWindow(seconds: 125), .closeCaptiveWindow])
        await transport.override(.error(.secureInstallRequired))
        await #expect(throws: DaemonError.secureInstallRequired) { try await app.openCaptiveWindow(seconds: 60) }
        await app.client.disconnect()
    }
}
