// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol
import WGEXProfileStore

@Suite(.timeLimit(.minutes(1)))
private struct Guest5AppCallbackTests {
    @Test(arguments: [false, true])
    func `idle imported app provides CLI up and cutover secrets over the callback wire`(cutover: Bool) async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let store = InMemorySecretStore(), appTransport = RecordingClientTransport(dispatcher, wireCallbacks: true)
        let key = try fixtureKey()
        try await service.expectPublicKey(PrivateKey(bytes: key).publicKey())
        let account = SecretID(profileID: service.id, kind: .privateKey)
        try await store.store(fixtureKey(), for: account)
        var profile = TunnelProfile(id: service.id, name: "Imported idle fixture")
        profile.secrets.privateKey = .daemonStore(id: account.id)
        let app = MacDaemonComposition(
            transport: appTransport, clientVersion: "1", clientBuild: 10, secretStore: store, systemOperationsPermitted: true,
        )
        try await app.start(profiles: [profile])
        #expect(await service.active == nil)
        #expect(await service.secretStarts == 0)
        let cliTransport = RecordingClientTransport(dispatcher)
        let cli = DaemonClient(transport: cliTransport, clientVersion: "1", clientBuild: 10)
        let arguments = cutover
            ? ["cutover", "start", profile.id.uuidString, "--confirm-within", "2m"]
            : ["up", profile.id.uuidString]
        let result = await WGEXCLICore(client: cli, service: CallbackCLIService()).run(arguments)
        #expect(result.exitCode == 0)
        #expect(await service.active == profile.id)
        #expect(await service.secretStarts == 1)
        #expect(await service.lastPrivateKeyMatches)
        #expect(await !cliTransport.secretsObserved)
        await app.client.disconnect(); await cli.disconnect()
    }

    @Test(arguments: [DaemonError.unauthorised, .malformedMessage, .disconnected])
    func `dispatcher exposes app callback refusal without arming an intent`(failure: DaemonError) async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501, pid: 1, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: { _ in throw failure }))
        for request: Request in [.hello(clientVersion: "1", clientBuild: 10), .subscribeEvents(includeLogs: false)] {
            _ = try await app.send(Envelope(body: request).encoded(), secrets: nil)
        }
        let cli = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        await #expect {
            _ = try await cli.request(.startCutover(profileID: service.id, confirmWithin: 120, hasSecrets: false))
        } throws: { error in
            guard let wire = error as? DaemonError else { return false }
            return failure == .disconnected ? wire == .protectionUnknown(reason: "secretsHandoffDisconnected") : wire == failure
        }
        #expect(await service.active == nil)
        #expect(await service.secretStarts == 0)
        await cli.disconnect(); await app.invalidate()
    }

    private func fixtureKey() throws -> SecretBytes {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 5 {
            root.deleteLastPathComponent()
        }
        var data = try Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/client1.key"))
        let input = try SecretBytes(wiping: &data)
        let range: Range<Int>? = input.withUnsafeBytes { raw in
            var start = 0
            for end in raw.indices where raw[end] == 10 {
                if start < end, raw[start] != 35 {
                    return start ..< (raw[end - 1] == 13 ? end - 1 : end)
                }
                start = end + 1
            }
            return nil
        }
        let text = try SecretBytes(copying: input, range: #require(range))
        let key = try PrivateKey(parsing: text, encoding: .base64)
        var bytes = try SecretBytes(zeroedCount: 32)
        try key.encode(into: &bytes)
        return bytes
    }
}

private struct CallbackCLIService: ServiceControlling {
    var state: AsyncStream<ServiceState> {
        AsyncStream { $0.finish() }
    }

    func register() async throws(ServiceError) {
        throw .hostGuard
    }

    func unregister() async throws(ServiceError) {
        throw .hostGuard
    }

    func openApproval() {}
}
