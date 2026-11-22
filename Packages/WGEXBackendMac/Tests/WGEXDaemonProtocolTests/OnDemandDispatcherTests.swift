// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

private actor EventLog {
    var events: [Event] = []
    func receive(_ bytes: Data) {
        if let event = try? WireCodec.decode(Event.self, from: bytes) {
            events.append(event)
        }
    }
}

/// ADR-030 section 8: protocol 8 rows, the recovery allowlist, the secrets method and eligible-reporter delivery.
private struct OnDemandDispatcherTests {
    private static let observation = WiFiObservation(interfaceName: "en0", reading: .ssid("Home"), observedAtContinuous: 1)

    private static func decide(_ request: Request, caller: uid_t = 501, console: Bool = true, app: Bool = false) -> AuthorisationDecision {
        AuthorisationTable.decide(
            request: request, callerUID: caller, isConsoleUser: console, hasAdminRight: false, ownerUID: 501, isAppClient: app,
        )
    }

    @Test
    func `protocol 8 rows authorise arm, disarm and the Wi-Fi report`() {
        let id = UUID()
        #expect(Self.decide(.armOnDemand(profileID: id, hasSecrets: true)) == .allow)
        #expect(Self.decide(.armOnDemand(profileID: id, hasSecrets: true), console: false) == .deny(.notConsoleUser))
        #expect(Self.decide(.armOnDemand(profileID: id, hasSecrets: false), caller: 0, console: false) == .allow)
        #expect(Self.decide(.armOnDemand(profileID: id, hasSecrets: true), caller: 502) == .deny(.notOwner))
        #expect(Self.decide(.disarmOnDemand(profileID: id), console: false) == .allow)
        #expect(Self.decide(.disarmOnDemand(profileID: id), caller: 0) == .deny(.notOwner))
        #expect(Self.decide(.reportWiFiNetwork(Self.observation), app: true) == .allow)
        #expect(Self.decide(.reportWiFiNetwork(Self.observation), app: false) == .deny(.notAppClient))
        #expect(Self.decide(.reportWiFiNetwork(Self.observation), console: false, app: true) == .deny(.notConsoleUser))
        #expect(Self.decide(.reportWiFiNetwork(Self.observation), caller: 0, console: false, app: true) == .deny(.notConsoleUser))
        #expect(Request.armOnDemand(profileID: id, hasSecrets: true).profileID == id)
        #expect(Request.disarmOnDemand(profileID: id).profileID == id)
        #expect(Request.reportWiFiNetwork(Self.observation).profileID == nil)
        for kind in [RequestKind.armOnDemand, .disarmOnDemand, .reportWiFiNetwork] {
            #expect(AuthorisationTable.rules[kind] != nil)
        }
        #expect(Envelope.currentProtocolVersion == 8)
    }

    @Test
    func `recovery admits disarm and refuses arm and reports`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, isAppClient: { _ in true }),
        )
        await dispatcher.setRecovering(true)
        let transport = try await handshaken(dispatcher)
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        #expect(try await call(transport, .disarmOnDemand(profileID: service.profile)) == .ok)
        #expect(try await call(transport, .armOnDemand(profileID: service.profile, hasSecrets: false)) == .error(.recovering))
        #expect(try await call(transport, .reportWiFiNetwork(Self.observation)) == .error(.recovering))
        #expect(await service.calls == [.disarmOnDemand(profileID: service.profile)])
    }

    @Test
    func `arm uses the separate secrets argument and the report is bounded`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, isAppClient: { _ in true }),
        )
        let transport = try await handshaken(dispatcher)
        #expect(try await call(transport, .armOnDemand(profileID: service.profile, hasSecrets: true)) == .error(.malformedMessage))
        #expect(try await call(transport, .armOnDemand(profileID: service.profile, hasSecrets: false), secrets: Data([1]))
            == .error(.malformedMessage))
        #expect(try await call(transport, .armOnDemand(profileID: service.profile, hasSecrets: false)) == .ok)
        _ = try await call(transport, .subscribeEvents(includeLogs: false))
        let long = WiFiObservation(interfaceName: "en0", reading: .ssid(String(repeating: "x", count: 33)), observedAtContinuous: 1)
        #expect(try await call(transport, .reportWiFiNetwork(long)) == .error(.malformedMessage))
        let badName = WiFiObservation(interfaceName: "en0; x", reading: .notAssociated, observedAtContinuous: 1)
        #expect(try await call(transport, .reportWiFiNetwork(badName)) == .error(.malformedMessage))
    }

    @Test
    func `a report counts only from a subscribed app connection`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, isAppClient: { $0.pid == 7 }),
        )
        let app = try await handshaken(dispatcher)
        #expect(try await call(app, .reportWiFiNetwork(Self.observation)) == .ok)
        #expect(await service.calls.isEmpty)
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        #expect(try await call(app, .reportWiFiNetwork(Self.observation)) == .ok)
        #expect(await service.calls == [.reportWiFiNetwork(Self.observation)])
        let cli = InMemoryXPCTransport(daemon: dispatcher, peer: testPeer(pid: 8))
        try await cli.connect(callbacks: .init())
        _ = try await call(cli, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(cli, .subscribeEvents(includeLogs: false))
        #expect(try await call(cli, .reportWiFiNetwork(Self.observation)) == .error(.notAuthorised(.notAppClient)))
    }

    @Test
    func `the Wi-Fi request reaches eligible reporters only and losing one tells the service`() async throws {
        let service = DispatcherService()
        let console = Mutex(true)
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in console.withLock { $0 } }, isAppClient: { $0.pid == 7 }),
        )
        let appLog = EventLog(), cliLog = EventLog()
        let app = try await handshaken(dispatcher, callbacks: .init(event: { await appLog.receive($0) }))
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        let cli = InMemoryXPCTransport(daemon: dispatcher, peer: testPeer(pid: 8))
        try await cli.connect(callbacks: .init(event: { await cliLog.receive($0) }))
        _ = try await call(cli, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(cli, .subscribeEvents(includeLogs: false))
        #expect(await dispatcher.eligibleWiFiReporterCount() == 1)
        await dispatcher.publish(.wifiNetworkRequested(interfaceName: "en0"), profileID: nil)
        for _ in 0 ..< 1000 where await appLog.events.isEmpty {
            await Task.yield()
        }
        #expect(await appLog.events == [.wifiNetworkRequested(interfaceName: "en0")])
        #expect(await cliLog.events.isEmpty)
        console.withLock { $0 = false }
        #expect(await dispatcher.eligibleWiFiReporterCount() == 0)
        await cli.invalidate()
        #expect(await service.reporterLosses == 0)
        await app.invalidate()
        #expect(await service.reporterLosses == 1)
    }
}
