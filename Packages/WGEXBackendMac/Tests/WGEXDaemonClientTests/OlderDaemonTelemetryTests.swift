// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

/// A protocol-8 daemon from before M03-T01: its request vocabulary has no `statusTelemetry`, so the envelope does not decode
/// and its `receive` answers `malformedMessage`, as `DaemonDispatcher.receive` does for any undecodable envelope.
private actor PreTelemetryTransport: XPCTransport {
    private let base: InMemoryXPCTransport
    private(set) var requests: [Request] = []

    init(_ dispatcher: DaemonDispatcher) {
        base = InMemoryXPCTransport(
            daemon: dispatcher, peer: .init(uid: 501, pid: 99, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
    }

    func connect(callbacks: XPCClientCallbacks) async throws {
        try await base.connect(callbacks: callbacks)
    }

    func send(_ envelope: Data, secrets: Data?) async throws -> Data {
        let request = try Envelope.decode(envelope).body
        requests.append(request)
        if case .statusTelemetry = request {
            return try WireCodec.encode(Reply.error(.malformedMessage))
        }
        return try await base.send(envelope, secrets: secrets)
    }

    func invalidate() async {
        await base.invalidate()
    }
}

private struct OlderDaemonService: ServiceControlling {
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

/// M03-T01 review round 1, item 3: protocol 8 keeps one exact version (ADR-030 section 8), so a newer CLI meets an older
/// daemon that cannot read the telemetry request; it falls back once to the ordinary status, the extra fields unavailable.
@Suite(.timeLimit(.minutes(1)))
private struct OlderDaemonTelemetryTests {
    private func rig() -> (PreTelemetryTransport, DaemonClient, WGEXCLICore) {
        let dispatcher = DaemonDispatcher(
            service: ClientService(), daemonVersion: "1.0", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let transport = PreTelemetryTransport(dispatcher)
        let client = DaemonClient(transport: transport, clientVersion: "1.0", clientBuild: 10)
        return (transport, client, WGEXCLICore(client: client, service: OlderDaemonService()))
    }

    private func json(_ result: CLIResult) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
    }

    @Test
    func `status and cutover status read the ordinary status, once, with the telemetry unavailable`() async throws {
        let (transport, client, cli) = rig()
        let status = await cli.run(["status", "--json"])
        let fields = try json(status)
        #expect(status.exitCode == 0)
        #expect(fields["phase"] as? String == "idle")
        #expect(fields["sequence"] as? UInt64 == 1)
        #expect(fields["journalPolicy"] is NSNull)
        // An older daemon keeps no startup record (DEC-018).
        #expect(fields["startup"] is NSNull)
        #if WGEX_LAB_BUILD
            #expect(fields["ownerPFToken"] is NSNull)
        #endif
        let cutover = await cli.run(["cutover", "status", "--json"])
        #expect(cutover.exitCode == 0)
        #expect(try json(cutover)["phase"] as? String == "idle")
        // One telemetry attempt per daemon instance; after its refusal the client asks that daemon for the ordinary status.
        #expect(await transport.requests == [
            .hello(clientVersion: "1.0", clientBuild: 10), .subscribeEvents(includeLogs: false), .statusTelemetry, .status, .status,
        ])
        await client.disconnect()
    }

    @Test
    func `down reports the stop it made instead of an unavailable status`() async throws {
        let (_, client, cli) = rig()
        let result = await cli.run(["down", "--json"])
        let fields = try json(result)
        #expect(result.exitCode == 0)
        #expect(fields["result"] as? String == "stopped")
        #expect(fields["statusAvailable"] == nil)
        await client.disconnect()
    }
}
