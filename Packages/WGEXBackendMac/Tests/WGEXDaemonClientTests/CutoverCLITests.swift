// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct CutoverCLIService: ServiceControlling {
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

private struct CutoverCLITests {
    @Test
    func `cutover start parses minutes and prints deadline and offline recovery commands`() async throws {
        let (service, _, transport, client) = clientFixture()
        var status = TunnelStatus.idle
        status.cutover = .armed(deadline: Date(timeIntervalSince1970: 1_700_000_600))
        await service.setStatus(status)
        _ = try await client.connect()
        await transport.override(.started(Generation(rawValue: 1)), for: .startCutover)
        let cli = WGEXCLICore(client: client, service: CutoverCLIService())
        let result = await cli.run(["cutover", "start", service.id.uuidString, "--confirm-within", "10m"])
        #expect(result.exitCode == 0)
        #expect(await transport.requests.contains(.startCutover(profileID: service.id, confirmWithin: 600, hasSecrets: false)))
        #expect(result.output.contains("2023-11-14T22:23:20Z"))
        #expect(result.output.contains("cutover confirm"))
        #expect(result.output.contains("cutover abort"))
        #expect(result.output.contains("/Library/Application Support/WGEX/journal.json"))
        #expect(result.output.contains("sudo /sbin/pfctl -a com.apple/wgex -F all"))
        let bootout = try #require(result.output.range(of: "sudo /bin/launchctl bootout"))
        let token = try #require(result.output.range(of: "plutil -extract pfToken"))
        #expect(bootout.lowerBound < token.lowerBound)
        await client.disconnect()
    }

    @Test(arguments: ["59s", "61m", "0m", "-1m", "999999999999999999999h", "10", "1.5m"])
    func `bad cutover windows never send a mutation`(_ window: String) async {
        let (_, _, transport, client) = clientFixture()
        let result = await WGEXCLICore(client: client, service: CutoverCLIService()).run([
            "cutover", "start", UUID().uuidString, "--confirm-within", window,
        ])
        #expect(result.exitCode == 2)
        #expect(await transport.requests.isEmpty)
        await client.disconnect()
    }

    @Test
    func `cutover controls and status JSON carry stable state`() async throws {
        let (service, _, transport, client) = clientFixture()
        var status = TunnelStatus.idle
        status.cutover = .rolledBack(reason: .timeout)
        await service.setStatus(status)
        let cli = WGEXCLICore(client: client, service: CutoverCLIService())
        for command in ["confirm", "abort", "status"] {
            #expect(await cli.run(["cutover", command, "--json"]).exitCode == 0)
        }
        #expect(await transport.requests.contains(.confirmCutover))
        #expect(await transport.requests.contains(.abortCutover))
        let result = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        let cutover = try #require(fields["cutover"] as? [String: Any])
        #expect(cutover["state"] as? String == "rolledBack")
        #expect(cutover["reason"] as? String == "timeout")
        await client.disconnect()
    }

    @Test(arguments: [DaemonError.disconnected, .protectionUnknown(reason: "cutoverRollbackIncomplete")], [false, true])
    func `cutover failures retain recovery commands in text and JSON`(_ error: DaemonError, _ json: Bool) async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(error), for: .abortCutover)
        let result = await WGEXCLICore(client: client, service: CutoverCLIService()).run(["cutover", "abort"] + (json ? ["--json"] : []))
        #expect(result.exitCode == (error == .disconnected ? 1 : 12))
        if json {
            let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
            #expect((fields["recovery"] as? String)?.contains("cutover abort") == true)
        } else {
            #expect(result.output.contains("cutover abort"))
            #expect(result.output.contains("pfctl -a com.apple/wgex -F all"))
        }
        await client.disconnect()
    }

    @Test(arguments: [DaemonError.tunnel(.timedOut), .busy])
    func `late cutover confirmation maps completed timeout and pending cleanup`(_ error: DaemonError) async throws {
        let (_, _, transport, client) = clientFixture()
        _ = try await client.connect()
        await transport.override(.error(error), for: .confirmCutover)
        let result = await WGEXCLICore(client: client, service: CutoverCLIService()).run(["cutover", "confirm"])
        #expect(result.exitCode == (error == .busy ? 13 : 8))
        await client.disconnect()
    }
}
