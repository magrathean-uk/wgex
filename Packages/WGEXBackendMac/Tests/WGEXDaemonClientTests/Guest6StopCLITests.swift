// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

/// M1-19 D15b at the CLI: after a failed full-tunnel start the daemon now answers the stop with ok once everything is
/// released and reports idle (Guest6FullTunnelTests, through the dispatcher), which `wgex down` prints as stopped with
/// exit 0. The guest's run-6 answer (backendUnavailable with failed/unknown) keeps its distinct exit 18.
private struct Guest6StopCLITests {
    private static func failedStart(_ id: UUID) -> TunnelStatus {
        var status = TunnelStatus.idle
        status.phase = .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false)
        status.protection = .unknown; status.protectionNote = .canaryFailed
        status.recoveryFailureReason = .blockingPolicyFailed; status.policyEnforcing = true; status.activeProfileID = id
        return status
    }

    @Test(arguments: [false, true])
    func `D15 down after a failed full-tunnel start prints stopped and exits zero once the daemon reports idle`(_ json: Bool) async {
        let (service, _, _, client) = clientFixture()
        await service.setStatus(Self.failedStart(service.id))
        await service.configureStop(status: .idle, error: nil)
        let cli = WGEXCLICore(client: client, service: Guest6StopCLIService())
        let result = await cli.run(["down", service.id.uuidString] + (json ? ["--json"] : []))
        #expect(result.exitCode == 0)
        if json {
            #expect(result.output.contains("\"result\":\"stopped\"") && result.output.contains("\"phase\":\"idle\""))
            #expect(result.output.contains("\"protectionNote\":null") && !result.output.contains("recoveryFailureReason"))
        } else {
            #expect(result.output == "stopped: idle (unprotected)\n")
        }
        await client.disconnect()
    }

    @Test
    func `D15 the run-6 daemon answer stays a distinct teardown-incomplete exit eighteen`() async {
        let (service, _, _, client) = clientFixture()
        var stuck = Self.failedStart(service.id)
        stuck.activeProfileID = nil; stuck.policyEnforcing = false; stuck.recoveryFailureReason = .reconciliationFailed
        await service.configureStop(status: stuck, error: .tunnel(.backendUnavailable))
        let result = await WGEXCLICore(client: client, service: Guest6StopCLIService()).run(["down", service.id.uuidString])
        #expect(result.exitCode == 18)
        #expect(result.output.hasPrefix("stop accepted: failed (unknown)\n"))
        await client.disconnect()
    }
}

private struct Guest6StopCLIService: ServiceControlling {
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
