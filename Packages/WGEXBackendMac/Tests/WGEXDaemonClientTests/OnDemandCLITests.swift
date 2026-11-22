// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct OnDemandCLIService: ServiceControlling {
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

/// ADR-030 section 8: `wgex on-demand <UUID> on|off`, the status `onDemand` object and the client capability.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandCLITests {
    @Test
    func `on-demand on and off send arm without secrets and disarm`() async {
        let (service, _, _, client) = clientFixture()
        let cli = WGEXCLICore(client: client, service: OnDemandCLIService())
        let id = service.id
        #expect(await cli.run(["on-demand", id.uuidString, "on"]) == CLIResult(exitCode: 0, output: "armed\n"))
        #expect(await cli.run(["on-demand", id.uuidString, "off", "--json"]) == CLIResult(
            exitCode: 0,
            output: "{\"result\":\"disarmed\"}\n",
        ))
        let requests = await service.requests
        #expect(requests.contains(.armOnDemand(profileID: id, hasSecrets: false)))
        #expect(requests.contains(.disarmOnDemand(profileID: id)))
        #expect(await cli.run(["on-demand", id.uuidString, "maybe"]).exitCode == 2)
        #expect(await cli.run(["on-demand", "not-a-uuid", "on"]).exitCode == 2)
        #expect(client.capabilities.contains(.onDemand))
        await client.disconnect()
    }

    @Test
    func `status shows the on-demand object without any SSID`() async throws {
        let (service, _, _, client) = clientFixture()
        let id = UUID()
        var status = TunnelStatus.idle
        status.onDemand = OnDemandStatus(
            armedProfileID: id, activated: false, network: .wifi, ssid: .unavailable(.noReporter),
            decision: .hold(.ssidUnavailable), evaluatedAtContinuous: 5,
        )
        await service.setStatus(status)
        let cli = WGEXCLICore(client: client, service: OnDemandCLIService())
        let json = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        let onDemand = try #require(fields["onDemand"] as? [String: Any])
        #expect(onDemand["armedProfileID"] as? String == id.uuidString)
        #expect(onDemand["activated"] as? Bool == false)
        #expect(onDemand["network"] as? String == "wifi")
        #expect(onDemand["ssid"] as? [String: String] == ["state": "unavailable", "reason": "noReporter"])
        #expect(onDemand["decision"] as? [String: String] == ["state": "hold", "reason": "ssidUnavailable"])
        #expect(onDemand["evaluatedAtContinuous"] as? Double == 5)
        let text = await cli.run(["status"])
        #expect(text.output
            .contains("onDemand: armed \(id.uuidString); network wifi; hold (ssidUnavailable); SSID unavailable (noReporter)"))
        await client.disconnect()
    }

    @Test
    func `status reports an on-demand activation in JSON and text`() async throws {
        let (service, _, _, client) = clientFixture()
        let id = UUID()
        var status = TunnelStatus.idle
        status.onDemand = OnDemandStatus(
            armedProfileID: id, activated: true, network: .ethernet, ssid: .notRequired, decision: .connect,
        )
        await service.setStatus(status)
        let cli = WGEXCLICore(client: client, service: OnDemandCLIService())
        let json = await cli.run(["status", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        let onDemand = try #require(fields["onDemand"] as? [String: Any])
        #expect(onDemand["activated"] as? Bool == true)
        #expect(await cli.run(["status"]).output.contains("onDemand: armed \(id.uuidString); activated; network ethernet"))
        await client.disconnect()
    }

    @Test
    func `a Wi-Fi request event reaches the app's request stream`() async throws {
        let service = ClientService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1.0", daemonBuild: 10, minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }, isAppClient: { _ in true }),
        )
        let client = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1.0", clientBuild: 10, jitter: { 1 })
        let requests = await client.wifiNetworkRequests()
        _ = try await client.connect()
        _ = try await client.request(.subscribeEvents(includeLogs: false))
        await dispatcher.publish(.wifiNetworkRequested(interfaceName: "en0"), profileID: nil)
        for await name in requests {
            #expect(name == "en0")
            break
        }
        await client.disconnect()
    }
}
