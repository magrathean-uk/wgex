// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol
import WGEXProfileStore

private struct SecureInstallClientTests {
    private func report(_ state: SecureInstallReport.State) -> SecureInstallReport {
        SecureInstallReport(
            state: state,
            bundlePath: "/Applications/WGEX.app",
            nonRootWritableEntries: state == .verified ? 0 : 1,
            isUnderApplications: true,
            bundleIdentity: .matched,
            daemonIdentity: .matched,
        )
    }

    @Test
    func `successful repair is retained when its follow up read fails`() async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(hasAdminRight: { _, _ in true }),
        )
        let client = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        await service.failRepairFollowUp()
        #expect(try await client.performSecureInstall().state == .verified)
        await client.disconnect()
    }

    @Test(arguments: [uid_t(502), 0])
    func `verified non owners can inspect secure install without reading tunnel status`(_ uid: uid_t) async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let client = DaemonClient(transport: InMemoryXPCTransport(
            daemon: dispatcher, peer: .init(uid: uid, pid: 99, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        ), clientVersion: "1", clientBuild: 10)
        #expect(try await client.secureInstallStatus().state == .verified)
        await #expect(throws: DaemonError.notAuthorised(.notOwner)) { _ = try await client.request(.status) }
        var statuses = client.statusUpdates().makeAsyncIterator()
        #expect(await statuses.next()?.protection == .unknown)
        await client.disconnect()
    }

    @Test(arguments: [SecureInstallReport.Reason.bundleWritable, .aclWritable, .wrappingKeyUnavailable, .wrappingKeyRepairFailed])
    func `composition repairs with an external right then reads authoritative status`(reason: SecureInstallReport.Reason) async throws {
        let service = ClientService()
        await service.configureInstall(report(.needsAttention(reason)), repaired: report(.verified))
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }, hasAdminRight: { form, _ in form == Data([0x42]) }),
        )
        let transport = RecordingClientTransport(dispatcher)
        let app = MacDaemonComposition(
            transport: transport, clientVersion: "1", clientBuild: 10, secretStore: InMemorySecretStore(),
            systemOperationsPermitted: true, authorizeSecureInstall: { Data([0x42]) },
        )
        #expect(try await app.secureInstall() == .verified)
        #expect(await transport.requests.suffix(3) == [.secureInstallStatus, .performSecureInstall, .secureInstallStatus])
        let envelopes = try await transport.envelopes.map(Envelope.decode)
        #expect(envelopes.filter { $0.body == .performSecureInstall }.map(\.authorization) == [Data([0x42])])
        #expect(envelopes.filter { $0.body != .performSecureInstall }.allSatisfy { $0.authorization == nil })
        #expect(await !transport.secretsObserved)
        await app.client.disconnect()
    }

    @Test(arguments: [
        (SecureInstallReport.State.verified, SecureInstallState.verified),
        (.inProgress, .checking),
        (.needsAttention(.notInApplications), .needsAttention(.notInApplications)),
        (.needsAttention(.wrongBundle), .needsAttention(.serviceNotVerified)),
        (.needsAttention(.identityMismatch), .needsAttention(.serviceNotVerified)),
        (.needsAttention(.inspectionFailed), .needsAttention(.serviceNotVerified)),
    ])
    func `unrepairable states do not request authorisation or repair`(
        _ state: SecureInstallReport.State, _ expected: SecureInstallState,
    ) async throws {
        let (service, _, transport, _) = clientFixture()
        await service.configureInstall(report(state))
        let app = MacDaemonComposition(
            transport: transport, clientVersion: "1", clientBuild: 10, secretStore: InMemorySecretStore(),
            systemOperationsPermitted: true, authorizeSecureInstall: { Issue.record("Unexpected authentication"); return Data() },
        )
        #expect(try await app.secureInstall() == expected)
        #expect(await !transport.requests.contains(.performSecureInstall))
        await app.client.disconnect()
    }

    @Test
    func `perform denial missing form and malformed report propagate without false verification`() async throws {
        let (_, _, transport, client) = clientFixture()
        await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) { _ = try await client.performSecureInstall() }
        await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
            _ = try await client.performSecureInstall(authorization: Data([0x11]))
        }
        await transport.override(.ok)
        await #expect(throws: DaemonError.malformedMessage) { _ = try await client.secureInstallStatus() }
        await client.disconnect()
    }

    @Test
    func `gate failure reaches connection observers while the daemon remains reachable`() async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        var updates = await client.connectionStates().makeAsyncIterator()
        #expect(await updates.next() == .connected(daemonBuild: 10))
        await transport.override(.error(.secureInstallRequired))
        await #expect(throws: DaemonError.secureInstallRequired) { _ = try await client.request(.openCaptiveWindow(seconds: 60)) }
        #expect(await updates.next() == .secureInstallRequired(daemonBuild: 10))
        #expect(await transport.connectionAttempts == 1)
        await transport.override(.secureInstall(report(.verified)))
        #expect(try await client.secureInstallStatus().state == .verified)
        #expect(await updates.next() == .connected(daemonBuild: 10))
        await client.disconnect()
    }

    @Test(arguments: [
        (SecureInstallReport.State.needsAttention(.bundleWritable), SecureInstallState.needsAttention(.bundleWritable)),
        (.needsAttention(.notRootOwned), .needsAttention(.bundleWritable)),
        (.needsAttention(.aclWritable), .needsAttention(.bundleWritable)),
        (.needsAttention(.wrappingKeyUnavailable), .needsAttention(.bundleWritable)),
        (.needsAttention(.notInApplications), .needsAttention(.notInApplications)),
        (.needsAttention(.identityMismatch), .needsAttention(.serviceNotVerified)),
        (.inProgress, .checking),
    ])
    func `composition maps the final daemon report`(_ state: SecureInstallReport.State, _ expected: SecureInstallState) async throws {
        let service = ClientService()
        await service.configureInstall(report(.needsAttention(.bundleWritable)), repaired: report(state))
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(hasAdminRight: { _, _ in true }),
        )
        let app = MacDaemonComposition(
            transport: InMemoryXPCTransport(daemon: dispatcher, peer: .init(
                uid: 501,
                pid: 99,
                auditSessionID: 1,
                codeSigningVerdict: .requirementSatisfied,
            )),
            clientVersion: "1", clientBuild: 10, secretStore: InMemorySecretStore(), systemOperationsPermitted: true,
            authorizeSecureInstall: { Data([0x42]) },
        )
        #expect(try await app.secureInstall() == expected)
        await app.client.disconnect()
    }
}
