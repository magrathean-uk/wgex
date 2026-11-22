// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct RecoveringDispatcherTests {
    @Test
    func `shorter captive window still requires admin during recovery`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        await dispatcher.setRecovering(true)
        let transport = try await handshaken(dispatcher)
        var settings = MacGlobalSettings.defaults; settings.captiveWindowSeconds = 60
        #expect(try await call(transport, .setGlobalSettings(settings)) == .error(.notAuthorised(.adminRightRequired)))
        #expect(try await call(transport, .performSecureInstall) == .error(.notAuthorised(.adminRightRequired)))
        #expect(try await call(transport, .setStartBeforeLoginIntent(profileID: service.profile, enabled: false)) == .ok)
        let foreign = try await handshaken(dispatcher, uid: 502)
        #expect(try await call(foreign, .removeProfile(service.profile, purgeSecrets: false)) == .error(.notAuthorised(.notOwner)))
    }

    @Test
    func `recovery gate admits only reads stops and tightening settings`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, hasAdminRight: { _, _ in true }),
        )
        await dispatcher.setRecovering(true)
        let transport = try await handshaken(dispatcher)
        for request in [Request.status, .secureInstallStatus, .stopCurrent(reason: .userRequested)] {
            #expect(try await call(transport, request) != .error(.recovering))
        }
        #expect(try await call(transport, .subscribeEvents(includeLogs: false)) == .ok)
        #expect(try await call(transport, .performSecureInstall) == .ok)
        var tighter = MacGlobalSettings.defaults; tighter.lockdown = true; tighter.allowLAN = false
        #expect(try await call(transport, .setGlobalSettings(tighter)) == .ok)
        tighter.captiveWindowSeconds = 60
        #expect(try await call(transport, .setGlobalSettings(tighter)) == .ok)
        for request in [
            Request.statistics,
            .logs(since: nil, limit: 1),
            .prepareForUpdate,
            .openCaptiveWindow(seconds: 10),
        ] {
            #expect(try await call(transport, request) == .error(.recovering))
        }
        var looser = MacGlobalSettings.defaults; looser.captiveWindowSeconds = 600
        #expect(try await call(transport, .setGlobalSettings(looser)) == .error(.recovering))
        await dispatcher.setRecovering(false)
        #expect(try await call(transport, .statistics) == .ok)
    }
}
