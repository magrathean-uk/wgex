// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct StatusCLIService: ServiceControlling {
    var state: AsyncStream<ServiceState> {
        AsyncStream { $0.finish() }
    }

    func register() async throws(ServiceError) {}
    func unregister() async throws(ServiceError) {}
    func openApproval() {}
}

/// A CLI whose daemon answers `statusTelemetry` with the given uninstall progress (M05-T14).
private func statusRig(uninstall: UninstallProgress?) async -> (WGEXCLICore, DaemonClient) {
    let (_, _, transport, client) = clientFixture()
    var telemetry = StatusTelemetry(status: .idle)
    telemetry.uninstall = uninstall
    await transport.override(.statusTelemetry(telemetry), for: .status)
    return (WGEXCLICore(client: client, service: StatusCLIService()), client)
}

private func jsonFields(_ result: CLIResult) throws -> [String: Any] {
    try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
}

private let removalHint = "open WGEX to finish removing the background service and login item"

/// M05-T14: `wgex status` reports the uninstall the daemon holds.
@Suite(.timeLimit(.minutes(1)))
private struct StatusCLITests {
    @Test
    func `a completed keep uninstall is in the JSON and the text`() async throws {
        let (cli, client) = await statusRig(uninstall: .init(completed: true, purgeState: false, pendingStep: nil))
        let result = await cli.run(["status", "--json"])
        let uninstall = try #require(jsonFields(result)["uninstall"] as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(uninstall["completed"] as? Bool == true)
        #expect(uninstall["purgeState"] as? Bool == false)
        #expect(uninstall["pendingStep"] is NSNull)
        #expect(await cli.run(["status"]) == CLIResult(
            exitCode: 0,
            output: "idle (unprotected)\nuninstall: completed; the service is uninstalled; \(removalHint)\n",
        ))
        await client.disconnect()
    }

    @Test
    func `a completed purge uninstall says purge`() async throws {
        let (cli, client) = await statusRig(uninstall: .init(completed: true, purgeState: true, pendingStep: nil))
        let json = await cli.run(["status", "--json"])
        let uninstall = try #require(jsonFields(json)["uninstall"] as? [String: Any])
        #expect(uninstall["completed"] as? Bool == true)
        #expect(uninstall["purgeState"] as? Bool == true)
        #expect(await cli.run(["status"]).output
            == "idle (unprotected)\nuninstall: completed (purge); the service is uninstalled; \(removalHint)\n")
        await client.disconnect()
    }

    @Test
    func `an uninstall in progress names the step still owed`() async throws {
        let (cli, client) = await statusRig(uninstall: .init(completed: false, purgeState: false, pendingStep: .removeRoutes))
        let json = await cli.run(["status", "--json"])
        let uninstall = try #require(jsonFields(json)["uninstall"] as? [String: Any])
        #expect(uninstall["completed"] as? Bool == false)
        #expect(uninstall["pendingStep"] as? String == "removeRoutes")
        let text = await cli.run(["status"])
        #expect(text.exitCode == 0)
        #expect(text.output == """
        idle (unprotected)
        uninstall: in progress; step removeRoutes pending; run wgex uninstall again to resume

        """)
        await client.disconnect()
    }

    @Test
    func `no uninstall leaves the text unchanged and the JSON field null`() async throws {
        let (cli, client) = await statusRig(uninstall: nil)
        let json = await cli.run(["status", "--json"])
        #expect(try jsonFields(json)["uninstall"] is NSNull)
        #expect(await cli.run(["status"]) == CLIResult(exitCode: 0, output: "idle (unprotected)\n"))
        await client.disconnect()
    }

    @Test
    func `stop and cutover status keep the uninstall field`() async throws {
        let (cli, client) = await statusRig(uninstall: .init(completed: true, purgeState: false, pendingStep: nil))
        let cutover = await cli.run(["cutover", "status", "--json"])
        #expect(try jsonFields(cutover)["uninstall"] is [String: Any])
        await client.disconnect()
    }
}
