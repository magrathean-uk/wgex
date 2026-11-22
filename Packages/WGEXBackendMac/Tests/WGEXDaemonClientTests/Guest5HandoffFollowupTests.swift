// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5HandoffFollowupTests {
    @Test(arguments: [false, true], [false, true])
    func `app and proxy disconnects render a handoff refusal for up and cutover`(cutover: Bool, proxy: Bool) async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let callback: @Sendable (UUID) async throws -> Data = proxy
            ? NSXPCDaemonListener.secretsCallback(proxy: { handler in
                handler(DaemonError.disconnected); return nil
            })
            : { @Sendable _ in throw DaemonError.disconnected }
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501, pid: 1, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: callback))
        for request: Request in [.hello(clientVersion: "1", clientBuild: 10), .subscribeEvents(includeLogs: false)] {
            _ = try await app.send(Envelope(body: request).encoded(), secrets: nil)
        }
        let client = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        let cli = WGEXCLICore(client: client, service: HandoffCLIService())
        let args = cutover ? ["cutover", "start", service.id.uuidString, "--confirm-within", "2m"] : ["up", service.id.uuidString]
        for json in [false, true] {
            let result = await cli.run(args + (json ? ["--json"] : []))
            #expect(result.exitCode == 3)
            #expect(result.output.contains("secretsHandoffDisconnected"))
            #expect(result.output.contains("app went away during the secrets handoff"))
            #expect(result.output.contains("open WGEX and keep it running with this profile imported"))
            #expect(result.output.contains(cutover ? "retry cutover start" : "retry up"))
            #expect(!result.output.contains("daemonUnavailable"))
        }
        #expect(await service.active == nil)
        #expect(await service.secretStarts == 0)
        let requests = await service.requests
        #expect(!requests.contains { request in
            switch request {
            case .startIntent(_, _, true), .startCutover(_, _, true): true
            default: false
            }
        })
        await client.disconnect(); await app.invalidate()
    }

    @Test(arguments: [false, true])
    func `root reaches the handoff owner gate and receives unauthorised`(cutover: Bool) async throws {
        let service = ClientService(), requested = Mutex(0)
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501, pid: 1, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: { _ in requested.withLock { $0 += 1 }; return Data() }))
        for request: Request in [.hello(clientVersion: "1", clientBuild: 10), .subscribeEvents(includeLogs: false)] {
            _ = try await app.send(Envelope(body: request).encoded(), secrets: nil)
        }
        let transport = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 0, pid: 2, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        let request: Request = cutover ? .startCutover(profileID: service.id, confirmWithin: 120, hasSecrets: false)
            : .startIntent(profileID: service.id, transport: nil, hasSecrets: false)
        await #expect(throws: DaemonError.unauthorised) { _ = try await client.request(request) }
        #expect(await service.requests == [request])
        let args = cutover ? ["cutover", "start", service.id.uuidString, "--confirm-within", "2m"] : ["up", service.id.uuidString]
        let result = await WGEXCLICore(client: client, service: HandoffCLIService()).run(args)
        #expect(result.exitCode == 4)
        #expect(result.output == "unauthorised\n")
        #expect(requested.withLock { $0 } == 0)
        #expect(await service.active == nil)
        #expect(await service.secretStarts == 0)
        await client.disconnect(); await app.invalidate()
    }

    @Test(arguments: [["up", "--help"], ["cutover", "start", "--help"]])
    func `start help explains the owner handoff refusal mapping`(_ args: [String]) async {
        let (_, _, transport, client) = clientFixture()
        let result = await WGEXCLICore(client: client, service: HandoffCLIService()).run(args)
        #expect(result.output.contains("owner: app secrets handoff"))
        #expect(result.output.contains("non-owner (including root): unauthorised (exit 4)"))
        #expect(result.output.contains("no app: secretsUnavailable (exit 3)"))
        #expect(result.output.contains("silent app: timedOut (exit 8)"))
        #expect(await transport.connectionAttempts == 0)
    }
}

private struct HandoffCLIService: ServiceControlling {
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
