// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct TelemetryCLIServiceState: ServiceControlling {
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

/// Owner of one profile; answers a start-before-login request with the configured refusal, or accepts it.
private actor TelemetryCLIService: DaemonService {
    let id = UUID(uuidString: "22222222-2222-2222-2222-222222222222") ?? UUID()
    private(set) var requests: [Request] = []
    private var refusal: DaemonError?

    func refuse(with error: DaemonError?) {
        refusal = error
    }

    func ownerUID(for profileID: UUID) -> uid_t? {
        profileID == id ? 501 : nil
    }

    func profileIDs(ownedBy uid: uid_t) -> Set<UUID> {
        uid == 501 ? [id] : []
    }

    func protectionOwnerUID() -> uid_t? {
        501
    }

    func activeProfileID() -> UUID? {
        nil
    }

    func currentSettings() -> MacGlobalSettings {
        .defaults
    }

    func handle(_ request: Request, context _: DaemonRequestContext, secrets _: consuming SecretBundle?) -> Reply {
        requests.append(request)
        switch request {
        case .status: return .status(.idle)
        case .setStartBeforeLoginIntent: return refusal.map { .error($0) } ?? .ok
        default: return .ok
        }
    }
}

private func telemetryFixture(
    journalPolicy: JournalPolicyName? = nil, ownerToken: String? = nil,
) -> (TelemetryCLIService, WGEXCLICore, DaemonClient) {
    let service = TelemetryCLIService()
    var measured = TunnelStatus.idle
    measured.sequence = 1
    measured.measuredAt = Date(timeIntervalSince1970: 1000)
    measured.measuredAtContinuous = 50
    let status = measured
    let dispatcher = DaemonDispatcher(
        service: service, daemonVersion: "1.0", daemonBuild: 10, minimumClientBuild: 5,
        authorisation: .init(isConsoleUser: { _ in true }),
        measureStatus: {
            #if WGEX_LAB_BUILD
                StatusMeasurement(status: status, ownerUID: 501, journalPolicy: journalPolicy, ownerPFToken: ownerToken)
            #else
                StatusMeasurement(status: status, ownerUID: 501, journalPolicy: journalPolicy)
            #endif
        },
    )
    let client = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1.0", clientBuild: 10, jitter: { 1 })
    return (service, WGEXCLICore(client: client, service: TelemetryCLIServiceState()), client)
}

/// M03-T01: `wgex status --json` telemetry and `wgex boot-intent`.
@Suite(.timeLimit(.minutes(1)))
private struct StatusTelemetryCLITests {
    private static let appRefusal = "Starting before login requires secure install and storing the key with the background service."

    @Test
    func `status JSON carries the sequence, the measurement time and the journal policy`() async throws {
        let (_, cli, client) = telemetryFixture(journalPolicy: .error, ownerToken: "4660")
        let result = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(fields["sequence"] as? UInt64 == 1)
        #expect(fields["measuredAt"] as? String == "1970-01-01T00:16:40Z")
        #expect(fields["journalPolicy"] as? String == "error")
        // The old fields keep their meaning.
        #expect(fields["phase"] as? String == "idle")
        #expect(fields["protection"] as? String == "unprotected")
        #expect(fields["policyEnforcing"] as? Bool == false)
        #expect(await cli.run(["status"]) == CLIResult(exitCode: 0, output: "idle (unprotected)\n"))
        await client.disconnect()
    }

    @Test
    func `the owner pf reference is printed in Lab builds only`() async throws {
        let (_, cli, client) = telemetryFixture(journalPolicy: .connected, ownerToken: "4660")
        let result = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        #if WGEX_LAB_BUILD
            #expect(fields["ownerPFToken"] as? String == "4660")
        #else
            #expect(fields["ownerPFToken"] == nil)
            #expect(!result.output.contains("4660"))
            #expect(!result.output.contains("ownerPFToken"))
        #endif
        await client.disconnect()
    }

    @Test
    func `a service without a journal reports a null policy`() async throws {
        let (_, cli, client) = telemetryFixture()
        let result = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        #expect(fields["journalPolicy"] is NSNull)
        await client.disconnect()
    }

    @Test
    func `boot-intent on and off send the app's start-before-login request`() async {
        let (service, cli, client) = telemetryFixture()
        let id = service.id
        #expect(await cli.run(["boot-intent", id.uuidString, "on"]) == CLIResult(exitCode: 0, output: "bootIntentOn\n"))
        #expect(await cli.run(["boot-intent", id.uuidString, "off", "--json"]) == CLIResult(
            exitCode: 0,
            output: "{\"result\":\"bootIntentOff\"}\n",
        ))
        let requests = await service.requests
        #expect(requests.contains(.setStartBeforeLoginIntent(profileID: id, enabled: true)))
        #expect(requests.contains(.setStartBeforeLoginIntent(profileID: id, enabled: false)))
        await client.disconnect()
    }

    @Test(arguments: [DaemonError.secureInstallRequired, .secretsUnavailable])
    func `boot-intent on refuses without secure install or a stored key in the app's words`(refusal: DaemonError) async throws {
        let (service, cli, client) = telemetryFixture()
        await service.refuse(with: refusal)
        let id = service.id
        let name = refusal == .secureInstallRequired ? "secureInstallRequired" : "secretsUnavailable"
        let code: Int32 = refusal == .secureInstallRequired ? 4 : 3
        #expect(await cli.run(["boot-intent", id.uuidString, "on"]) == CLIResult(
            exitCode: code, output: "\(name): \(Self.appRefusal)\n",
        ))
        let json = await cli.run(["boot-intent", id.uuidString, "on", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        #expect(json.exitCode == code)
        #expect(fields["error"] as? String == name)
        #expect(fields["message"] as? String == Self.appRefusal)
        await client.disconnect()
    }

    @Test
    func `boot-intent needs a profile UUID and on or off`() async {
        let (service, cli, client) = telemetryFixture()
        let id = service.id
        #expect(await cli.run(["boot-intent", "not-a-uuid", "on"]).exitCode == 2)
        #expect(await cli.run(["boot-intent", id.uuidString, "maybe"]).exitCode == 2)
        #expect(await cli.run(["boot-intent", id.uuidString]).exitCode == 2)
        #expect(await service.requests.isEmpty)
        await client.disconnect()
    }
}
