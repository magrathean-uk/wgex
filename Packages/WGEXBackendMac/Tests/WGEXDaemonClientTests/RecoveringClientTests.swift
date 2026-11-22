// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct RecoveringClientTests {
    @Test
    func `client subscribes during recovery and keeps status reachable`() async throws {
        let service = ClientService()
        var status = TunnelStatus.idle
        status.protection = .blocked; status.recoveryFailureReason = .noPrimaryInterface
        await service.setStatus(status)
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1)
        await dispatcher.setRecovering(true)
        let transport = RecordingClientTransport(dispatcher)
        let client = DaemonClient(transport: transport, clientVersion: "test", clientBuild: 10)
        _ = try await client.connect()
        #expect(try await matches(client.request(.status), status: status))
        await #expect(throws: DaemonError.recovering) { _ = try await client.request(.statistics) }
        #expect(!DaemonError.recovering.userMessage.contains("protection is blocked"))
        #expect(DaemonError.recovering.tunnelError == .serviceRecovering)
        await dispatcher.setRecovering(false)
        #expect(try await matches(client.request(.status), status: status))
        #expect(await transport.requests.filter { $0 == .subscribeEvents(includeLogs: false) }.count == 1)
    }
}

private func matches(_ reply: Reply, status: TunnelStatus) -> Bool {
    guard case let .status(actual) = reply else { return false }
    #expect(actual.phase == status.phase)
    #expect(actual.protection == status.protection)
    #expect(actual.transport == status.transport)
    #expect(actual.health == status.health)
    #expect(actual.recentEvents == status.recentEvents)
    #expect(actual.recoveryFailureReason == status.recoveryFailureReason)
    #expect(actual.activeProfileID == status.activeProfileID)
    #expect(actual.operationInFlight == status.operationInFlight)
    #expect(actual.policyEnforcing == status.policyEnforcing)
    #expect(actual.verifiedAt == status.verifiedAt)
    #expect(actual.verifiedAtContinuous == status.verifiedAtContinuous)
    #expect(actual.sequence > 0)
    #expect(actual.measuredAt != nil)
    #expect(actual.measuredAtContinuous != nil)
    return true
}
