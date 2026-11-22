// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct Guest5CLITests {
    @Test
    func `D9 no app cutover refusal tells the owner to keep WGEX open without connecting`() async throws {
        let (service, _, _, client) = clientFixture()
        _ = try await client.connect()
        let result = await WGEXCLICore(client: client, service: Guest5CLIService()).run([
            "cutover",
            "start",
            service.id.uuidString,
            "--confirm-within",
            "1m",
        ])
        #expect(result.exitCode == 3)
        #expect(result.output
            .contains("open WGEX and keep it running with this profile imported; leave the tunnel disconnected, then retry cutover start"))
        await client.disconnect()
    }

    @Test
    func `D10 status text and JSON print the DNS protection note`() async {
        let (service, _, _, client) = clientFixture()
        var status = TunnelStatus.idle
        status.protection = .unknown; status.protectionNote = ProtectionNote(rawValue: 2)
        await service.setStatus(status)
        let cli = WGEXCLICore(client: client, service: Guest5CLIService())
        #expect(await cli.run(["status"]).output.contains("dnsUnverified"))
        #expect(await cli.run(["status", "--json"]).output.contains("dnsUnverified"))
        await client.disconnect()
    }
}

private struct Guest5CLIService: ServiceControlling {
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
