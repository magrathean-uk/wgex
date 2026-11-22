// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    @testable import WGEXDaemonProtocol
    import WGEXProfileStore

    /// Secure Install, the update hand-off and settings writes after a real approval: the app's grant crosses to the
    /// daemon, whose production recheck runs over the modelled read-back.
    private struct AdminApprovalFlowTests {
        private func report(_ state: SecureInstallReport.State) -> SecureInstallReport {
            SecureInstallReport(
                state: state, bundlePath: "/Applications/WGEX.app", nonRootWritableEntries: state == .verified ? 0 : 1,
                isUnderApplications: true, bundleIdentity: .matched, daemonIdentity: .matched,
            )
        }

        private func dispatcher(_ service: ClientService, _ authd: ModelledAuthd, daemonBuild: Int = 10) -> DaemonDispatcher {
            DaemonDispatcher(
                service: service, daemonVersion: "1", daemonBuild: daemonBuild, minimumClientBuild: 1, authorisation: authd.authorisation,
            )
        }

        @Test(arguments: [false, true])
        func `secure install succeeds after an approval and fails closed when it is stale`(stale: Bool) async throws {
            let authd = try ModelledAuthd.fixture()
            let service = ClientService()
            await service.configureInstall(report(.needsAttention(.bundleWritable)), repaired: report(.verified))
            let app = MacDaemonComposition(
                transport: RecordingClientTransport(dispatcher(service, authd)), clientVersion: "1", clientBuild: 10,
                secretStore: InMemorySecretStore(), systemOperationsPermitted: true, authorizeSecureInstall: {
                    let form = authd.approve()
                    if stale {
                        authd.advance(31)
                    }
                    return form
                },
            )
            if stale {
                await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) { _ = try await app.secureInstall() }
                #expect(await !service.requests.contains(.performSecureInstall))
            } else {
                #expect(try await app.secureInstall() == .verified)
                #expect(await service.requests.contains(.performSecureInstall))
            }
            #expect(authd.recheckFlags == [[]])
            await app.client.disconnect()
        }

        @Test func `the update hand-off is admitted after an approval`() async throws {
            let authd = try ModelledAuthd.fixture()
            let service = ClientService()
            let client = DaemonClient(
                transport: RecordingClientTransport(dispatcher(service, authd, daemonBuild: 9)),
                clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 1,
            )
            let registration = ApprovingService()
            let states = Mutex<[UpdateHandoffState]>([])
            try await DaemonUpdateHandoff.run(
                client: client, service: registration, currentBuild: 10, grant: authd.approve(),
                changed: { state in states.withLock { $0.append(state) } },
            )
            #expect(await service.requests.contains(.prepareForUpdate))
            #expect(registration.calls.withLock { $0 } == ["unregister", "register"])
            #expect(states.withLock { $0 } == [.finishing, .ready])
            #expect(authd.recheckFlags == [[]])
            await client.disconnect()
        }

        @Test func `an update hand-off without a fresh approval never registers`() async throws {
            let authd = try ModelledAuthd.fixture()
            let client = DaemonClient(
                transport: RecordingClientTransport(dispatcher(ClientService(), authd, daemonBuild: 9)),
                clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 1,
            )
            let registration = ApprovingService()
            await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
                try await DaemonUpdateHandoff.run(
                    client: client, service: registration, currentBuild: 10, grant: authd.unapproved(), changed: { _ in },
                )
            }
            #expect(registration.calls.withLock { $0.isEmpty })
            await client.disconnect()
        }

        @Test func `a loosening settings write succeeds only with an approval`() async throws {
            let authd = try ModelledAuthd.fixture()
            let service = ClientService()
            let client = DaemonClient(transport: RecordingClientTransport(dispatcher(service, authd)), clientVersion: "1", clientBuild: 10)
            var loosened = MacGlobalSettings.defaults
            loosened.captiveWindowSeconds = 600
            await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
                _ = try await client.request(.setGlobalSettings(loosened), authorization: nil)
            }
            let stale = authd.approve()
            authd.advance(31)
            await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
                _ = try await client.request(.setGlobalSettings(loosened), authorization: stale)
            }
            #expect(await !service.requests.contains(.setGlobalSettings(loosened)))
            #expect(try await client.request(.setGlobalSettings(loosened), authorization: authd.approve()) == .ok)
            #expect(await service.requests.filter { $0 == .setGlobalSettings(loosened) }.count == 1)
            await client.disconnect()
        }
    }

    /// Registration that is enabled as soon as it is replaced.
    private final class ApprovingService: ServiceControlling {
        let calls = Mutex<[String]>([])
        private let updates = AsyncStream<ServiceState>.makeStream()
        var state: AsyncStream<ServiceState> {
            updates.stream
        }

        func register() async throws(ServiceError) {
            calls.withLock { $0.append("register") }
            updates.continuation.yield(.enabled)
        }

        func unregister() async throws(ServiceError) {
            calls.withLock { $0.append("unregister") }
        }

        func openApproval() {}
    }
#endif
