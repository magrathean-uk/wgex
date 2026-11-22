// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct CLIServiceState: ServiceControlling {
    var state: AsyncStream<ServiceState> {
        AsyncStream { $0.yield(.requiresApproval); $0.finish() }
    }

    func register() async throws(ServiceError) {
        throw .hostGuard
    }

    func unregister() async throws(ServiceError) {
        throw .hostGuard
    }

    func openApproval() {}
}

private struct CLITests {
    @Test
    func `recovery status exposes the integer reason without adapter text`() async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        status.protection = .blocked; status.recoveryFailureReason = .noPrimaryInterface
        await service.setStatus(status)
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        let result = await cli.run(["status", "--json"])
        #expect(result.exitCode == 0)
        #expect(result.output.contains("\"recoveryFailureReason\":1"))
        await client.disconnect()
    }

    @Test
    func `status text and JSON goldens`() async throws {
        let (_, _, _, client) = clientFixture()
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        #expect(await cli.run(["status"]) == CLIResult(exitCode: 0, output: "idle (unprotected)\n"))
        let result = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(fields["phase"] as? String == "idle")
        // One status read per command: connection setup takes none of its own (M03-T01 review 1), so the second command reads 2.
        #expect(fields["sequence"] as? UInt64 == 2)
        #expect(fields["activeProfileID"] is NSNull)
        #expect(fields["measuredAt"] is String)
        #expect(fields["measuredAtContinuous"] is Double)
        #expect(fields["verifiedAt"] is NSNull)
        #expect(fields["verifiedAtContinuous"] is NSNull)
        #expect(fields["policyEnforcing"] as? Bool == false)
        #expect(fields["operationInFlight"] as? Bool == false)
        await client.disconnect()
    }

    @Test
    func `doctor identifiers reachability service and secure install goldens`() async {
        let (_, _, _, client) = clientFixture()
        let ids = BuildIdentifiers(base: "com.example.fixture.dev", team: "TESTTEAM00")
        let cli = WGEXCLICore(client: client, service: CLIServiceState(), identifiers: ids, plistExists: { true })
        let expected = "app: com.example.fixture.dev\ncli: com.example.fixture.dev.cli\ndaemon: com.example.fixture.dev.daemon\n"
            + "daemonReachable: true\nserviceState: requiresApproval\nsecureInstall: verified\n"
        #expect(await cli.run(["doctor"]) == CLIResult(exitCode: 0, output: expected))
        let json = "{\"app\":\"com.example.fixture.dev\",\"cli\":\"com.example.fixture.dev.cli\","
            + "\"daemon\":\"com.example.fixture.dev.daemon\",\"daemonReachable\":true,"
            + "\"secureInstall\":\"verified\",\"serviceState\":\"requiresApproval\"}\n"
        #expect(await cli.run(["doctor", "--json"]) == CLIResult(exitCode: 0, output: json))
        await client.disconnect()
    }

    @Test
    func `up has no secret store and down routes through owner checked dispatcher`() async {
        let (service, _, _, client) = clientFixture()
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        #expect(await cli.run(["up", service.id.uuidString]) == CLIResult(
            exitCode: 3,
            output: "secretsUnavailable: open WGEX to connect\n",
        ))
        #expect(await cli.run(["up", service.id.uuidString, "--json"]) == CLIResult(
            exitCode: 3,
            output: "{\"error\":\"secretsUnavailable\"}\n",
        ))
        #expect(await cli.run(["down"]) == CLIResult(exitCode: 0, output: "stopped: idle (unprotected)\n"))
        let stopped = await cli.run(["down", service.id.uuidString, "--json"])
        #expect(stopped.exitCode == 0)
        #expect(stopped.output.contains("\"result\":\"stopped\""))
        #expect(stopped.output.contains("\"phase\":\"idle\""))
        #expect(await service.requests.contains(.stop(profileID: service.id, reason: .userRequested)))
        #expect(await cli.run(["up", "bad-id", "--json"]) == CLIResult(exitCode: 2, output: "{\"error\":\"usage\"}\n"))
        await client.disconnect()
    }

    @Test(arguments: [false, true], [false, true])
    func `up and cutover report no underlay resolver answer with fixed copy`(_ cutover: Bool, _ json: Bool) async {
        let (service, _, transport, client) = clientFixture()
        await transport.override(
            .error(.protectionUnknown(reason: "underlayResolverNoAnswer")),
            for: cutover ? .startCutover : .startIntent,
        )
        let args = cutover ? ["cutover", "start", service.id.uuidString, "--confirm-within", "60s"] : ["up", service.id.uuidString]
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(args + (json ? ["--json"] : []))
        #expect(result.exitCode == 8)
        #expect(result.output.contains("underlayResolverNoAnswer"))
        #expect(result.output.contains("No answer from the underlay resolver"))
        #expect(!result.output.contains("daemonUnavailable"))
        await client.disconnect()
    }

    @Test
    func `doctor reports unavailable daemon without service mutations`() async {
        let (_, _, transport, client) = clientFixture()
        await transport.failConnections(1)
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        let result = await cli.run(["doctor", "--json"])
        #expect(result.exitCode == 1)
        #expect(result.output.contains("\"daemonReachable\":false"))
        await client.disconnect()
    }

    @Test(arguments: [false, true])
    func `doctor outside the app reports unavailable without querying service state`(_ reachable: Bool) async throws {
        let (_, _, transport, client) = clientFixture()
        if !reachable {
            await transport.failConnections(2)
        }
        let queried = Mutex(false)
        let service = ServiceController(
            operations: .init(register: {}, unregister: {}, status: { queried.withLock { $0 = true }; return .notFound }, openApproval: {}),
            isDebugBuild: false,
        )
        let cli = WGEXCLICore(client: client, service: service, plistExists: { false })
        let text = await cli.run(["doctor"])
        #expect(text.exitCode == (reachable ? 0 : 1))
        #expect(text.output.contains("serviceState: unavailable (query from the app; the CLI runs outside the app bundle)\n"))
        #expect(text.output.contains("daemonReachable: \(reachable)\n"))
        let json = await cli.run(["doctor", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        #expect(fields["serviceState"] as? String == "unavailable (query from the app; the CLI runs outside the app bundle)")
        #expect(fields["daemonReachable"] as? Bool == reachable)
        #expect(!queried.withLock { $0 })
        await client.disconnect()
    }
}

private struct CLIFailureCategoriesTests {
    @Test
    func `down without UUID resolves the current intent before reporting acceptance`() async {
        let (service, _, _, client) = clientFixture()
        await service.configureStop(status: .idle, error: .tunnel(.backendUnavailable))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["down"])
        #expect(result == CLIResult(exitCode: 0, output: "stopped: idle (unprotected)\n"))
        #expect(await service.requests.contains(.stop(profileID: service.id, reason: .userRequested)))
        await client.disconnect()
    }

    @Test(arguments: [false, true])
    func `acknowledged down cannot claim completion when the resulting status is unavailable`(_ json: Bool) async throws {
        let (service, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(.disconnected), for: .status)
        let args = ["down", service.id.uuidString] + (json ? ["--json"] : [])
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(args)
        #expect(result.exitCode == 12)
        #expect(result
            .output == (json ? "{\"result\":\"stopAccepted\",\"statusAvailable\":false}\n" : "stop accepted (status unavailable)\n"))
        await client.disconnect()
    }

    @Test(arguments: [false, true], [false, true])
    func `down accepted during recovery reports the resulting status honestly`(_ teardownError: Bool, _ failedStatus: Bool) async {
        let (service, dispatcher, _, client) = clientFixture()
        var status = TunnelStatus.idle
        if failedStatus {
            status.phase = .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false)
            status.protection = .unknown
            status.recoveryFailureReason = .reconciliationFailed
        }
        await service.configureStop(status: status, error: teardownError ? .tunnel(.backendUnavailable) : nil)
        await dispatcher.setRecovering(true)
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        let text = await cli.run(["down", service.id.uuidString])
        #expect(text == CLIResult(
            exitCode: failedStatus ? 18 : 0,
            output:
            failedStatus ? "stop accepted: failed (unknown)\n" : "stopped: idle (unprotected)\n",
        ))
        let json = await cli.run(["down", service.id.uuidString, "--json"])
        #expect(json.exitCode == (failedStatus ? 18 : 0))
        #expect(json.output.contains(failedStatus ? "\"result\":\"stopAccepted\"" : "\"result\":\"stopped\""))
        #expect(json.output.contains(failedStatus ? "\"phase\":\"failed\"" : "\"phase\":\"idle\""))
        #expect(json.output.contains("\"recoveryFailureReason\":6") == failedStatus)
        await client.disconnect()
    }

    @Test(arguments: [false, true])
    func `down protectionUnknown retains exit twelve and prints the measured status`(_ failed: Bool) async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        if failed {
            status.phase = .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false)
            status.protection = .unknown; status.recoveryFailureReason = .reconciliationFailed
        }
        await service.configureStop(status: status, error: .protectionUnknown(reason: "opaque adapter detail"))
        let cli = WGEXCLICore(client: client, service: CLIServiceState())
        let text = await cli.run(["down", service.id.uuidString])
        #expect(text == CLIResult(
            exitCode: 12,
            output:
            failed ? "protectionUnknown: failed (unknown)\n" : "protectionUnknown: idle (unprotected)\n",
        ))
        let json = await cli.run(["down", service.id.uuidString, "--json"])
        #expect(json.exitCode == 12)
        #expect(json.output.contains("\"error\":\"protectionUnknown\""))
        #expect(json.output.contains(failed ? "\"phase\":\"failed\"" : "\"phase\":\"idle\""))
        #expect(json.output.contains("\"recoveryFailureReason\":6") == failed)
        #expect(!json.output.contains("opaque adapter detail"))
        await client.disconnect()
    }

    @Test(arguments: [
        TunnelPhase.active(Generation(rawValue: 2)), .stopping(Generation(rawValue: 2), reason: .userRequested),
    ])
    func `acknowledged down only exits zero for an idle resulting phase`(_ phase: TunnelPhase) async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        status.phase = phase
        await service.configureStop(status: status, error: nil)
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["down", service.id.uuidString, "--json"])
        #expect(result.exitCode == 18)
        #expect(result.output.contains("\"result\":\"stopAccepted\""))
        await client.disconnect()
    }

    @Test(arguments: [false, true])
    func `down never accepts an error while intent or operation remains`(_ inFlight: Bool) async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        status.activeProfileID = inFlight ? nil : service.id
        status.operationInFlight = inFlight
        await service.configureStop(status: status, error: .tunnel(.backendUnavailable))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["down", service.id.uuidString])
        #expect(result.exitCode != 0)
        #expect(!result.output.contains("stopped"))
        await client.disconnect()
    }

    @Test(arguments: [DaemonError.disconnected, .recovering, .notAuthorised(.notOwner)])
    func `down keeps transport recovery and authorisation errors as failures`(_ error: DaemonError) async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(error))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["down"])
        #expect(result.exitCode != 0)
        #expect(!result.output.contains("stopped"))
        await client.disconnect()
    }

    @Test(arguments: [
        (DaemonError.tunnel(.busy), "busy", Int32(13)),
        (.busy, "busy", 13),
        (.tunnel(.revisionConflict), "revisionConflict", 18),
        (.onDemandNotConfigured, "onDemandNotConfigured", 7),
    ])
    func `merged tunnel errors retain distinct CLI categories`(_ error: DaemonError, _ category: String, _ code: Int32) async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(error))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["up", UUID().uuidString, "--json"])
        #expect(result == CLIResult(exitCode: code, output: "{\"error\":\"\(category)\"}\n"))
        await client.disconnect()
    }

    @Test(arguments: [
        (DaemonError.tunnel(.timedOut), Int32(8)), (.tunnel(.engine(code: -5)), 9), (.tunnel(.cancelled), 10),
        (.anotherTunnelActive, 6), (.recovering, 5), (.protectionUnknown(reason: "fixed"), 12),
        (.multipleBootProfiles, 7), (.tunnel(.invalidConfiguration(.invalidProfile)), 7), (.onDemandNotConfigured, 7),
    ])
    func `CLI preserves typed failure categories`(_ error: DaemonError, _ code: Int32) async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(error))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["up", UUID().uuidString])
        #expect(result.exitCode == code)
        #expect(!result.output.contains("protection is blocked"))
        await client.disconnect()
    }

    @Test
    func `reading a failed status succeeds and keeps the state in JSON`() async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        status.phase = .failed(.engine(code: -5), blockedByPolicy: false, needsSecrets: false)
        await service.setStatus(status)
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["status", "--json"])
        #expect(result.exitCode == 0)
        #expect(result.output.contains("\"phase\":\"failed\""))
        await client.disconnect()
    }

    @Test
    func `status read errors still have a non zero typed exit code`() async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(.notAuthorised(.notOwner)))
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["status", "--json"])
        #expect(result.exitCode == 4)
        #expect(result.output.contains("unauthorised"))
        await client.disconnect()
    }

    @Test
    func `recovering CLI reports measured unprotected instead of inventing blocking`() async {
        let (service, dispatcher, _, client) = clientFixture()
        await dispatcher.setRecovering(true)
        let result = await WGEXCLICore(client: client, service: CLIServiceState()).run(["up", service.id.uuidString])
        #expect(result.exitCode == 5)
        #expect(result.output.contains("protection=unprotected"))
        await client.disconnect()
    }
}
