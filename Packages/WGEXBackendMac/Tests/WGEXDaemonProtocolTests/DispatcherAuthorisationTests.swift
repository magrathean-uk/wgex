// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct DispatcherAuthorisationTests {
    private static func requests(_ id: UUID) -> [Request] {
        [
            .hello(clientVersion: "1", clientBuild: 11), .installProfile(.init(
                profile: TunnelProfile(id: id, name: "Fixture"),
                revision: 1,
            )),
            .removeProfile(id, purgeSecrets: false), .startIntent(profileID: id, transport: nil, hasSecrets: false),
            .stop(profileID: id, reason: .userRequested), .stopCurrent(reason: .userRequested),
            .selectTransport(profileID: id, transport: nil), .setGlobalSettings(.defaults),
            .openCaptiveWindow(seconds: 60), .extendCaptiveWindow(seconds: 60), .closeCaptiveWindow,
            .subscribeEvents(includeLogs: true), .setStartBeforeLoginIntent(profileID: id, enabled: false),
            .secureInstallStatus, .performSecureInstall, .status, .statistics, .logs(since: nil, limit: 10), .diagnostics(.init(
                includeLogs: true,
                since: nil,
                profileIDs: [id],
            )),
            .prepareForUpdate, .uninstall(purgeState: false),
            .startCutover(profileID: id, confirmWithin: 600, hasSecrets: false), .confirmCutover, .abortCutover,
            .armOnDemand(profileID: id, hasSecrets: false), .disarmOnDemand(profileID: id),
            .reportWiFiNetwork(WiFiObservation(interfaceName: "en0", reading: .notAssociated, observedAtContinuous: 1)),
        ]
    }

    @Test(arguments: [uid_t(501), 502, 0], [(false, false), (false, true), (true, false), (true, true)])
    func `dispatcher enforces every table row`(uid: uid_t, flags: (Bool, Bool)) async throws {
        let (console, admin) = flags
        let service = DispatcherService()
        let requests = Self.requests(service.profile)
        #expect(Set(requests.map(\.kind)) == Set(RequestKind.allCases))
        // The app identity follows the admin flag, so both reporter denials (not the app, not the console) are covered.
        let policy = DaemonAuthorisation(isConsoleUser: { _ in console }, hasAdminRight: { _, _ in admin }, isAppClient: { _ in admin })
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 9,
            minimumClientBuild: 1,
            authorisation: policy,
        )
        let transport = try await handshaken(dispatcher, uid: uid)
        for request in requests {
            // Collection requests use the caller's scope; explicit and global state requests use owner 501.
            let owner: uid_t? = switch request {
            case .logs, .diagnostics, .subscribeEvents, .hello, .uninstall, .prepareForUpdate, .closeCaptiveWindow, .reportWiFiNetwork: uid
            default: 501
            }
            let expected = AuthorisationTable.decide(
                request: request, callerUID: uid, isConsoleUser: console, hasAdminRight: admin,
                ownerUID: owner, currentSettings: .defaults, clientIsNewer: true, isAppClient: admin,
            )
            let result = try await call(transport, request)
            switch expected {
            case let .deny(reason): #expect(result == .error(.notAuthorised(reason)))
            case .allow:
                if case .error(.notAuthorised) = result {
                    Issue.record("Allowed table row denied: \(request.kind)")
                }
            }
        }
    }

    @Test
    func `cross uid cannot tighten or loosen global protection without a right`() async throws {
        let service = DispatcherService()
        let policy = DaemonAuthorisation(isConsoleUser: { _ in true })
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: policy,
        )
        let transport = try await handshaken(dispatcher, uid: 502)
        var tighter = MacGlobalSettings.defaults
        tighter.lockdown = true
        #expect(try await call(transport, .setGlobalSettings(tighter)) == .error(.notAuthorised(.notOwner)))
        tighter.captiveWindowSeconds += 1
        #expect(try await call(transport, .setGlobalSettings(tighter)) == .error(.notAuthorised(.adminRightRequired)))
        #expect(await service.calls.isEmpty)
    }
}
