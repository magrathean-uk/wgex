// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct UninstallCLIService: ServiceControlling {
    var state: AsyncStream<ServiceState> {
        AsyncStream { $0.finish() }
    }

    func register() async throws(ServiceError) {}
    func unregister() async throws(ServiceError) {}
    func openApproval() {}
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var count: Int {
        lock.withLock { value }
    }

    func bump() {
        lock.withLock { value += 1 }
    }
}

private struct Rig {
    let service: ClientService
    let transport: RecordingClientTransport
    let client: DaemonClient
    let cli: WGEXCLICore
    let grants = Counter()
    let questions = Counter()

    init(interactive: Bool = true, answer: Bool = true, grantFails: Bool = false) {
        let (service, _, transport, client) = clientFixture()
        let grants = grants, questions = questions
        self.service = service; self.transport = transport; self.client = client
        cli = WGEXCLICore(
            client: client, service: UninstallCLIService(),
            grant: {
                grants.bump()
                if grantFails {
                    throw DaemonError.notAuthorised(.adminRightRequired)
                }
                return Data([1, 2, 3])
            },
            console: CLIConsole(isInteractive: interactive) { _ in questions.bump(); return answer },
        )
    }

    func uninstallRequests() async -> [Request] {
        await transport.requests.filter { $0.kind == .uninstall }
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct UninstallCLITests {
    @Test
    func `confirmed uninstall calls the daemon and says what to do next`() async {
        let rig = Rig()
        await rig.transport.override(.ok, for: .uninstall)
        let result = await rig.cli.run(["uninstall"])
        #expect(result.exitCode == 0)
        #expect(result.output.contains("open WGEX to finish removing the background service and login item"))
        #expect(await rig.uninstallRequests() == [.uninstall(purgeState: false)])
        #expect(rig.questions.count == 1 && rig.grants.count == 1)
        await rig.client.disconnect()
    }

    @Test
    func `purge and yes skip the question and send purge`() async throws {
        let rig = Rig(interactive: false)
        await rig.transport.override(.ok, for: .uninstall)
        let result = await rig.cli.run(["uninstall", "--purge", "--yes", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(fields["result"] as? String == "uninstalled" && fields["purge"] as? Bool == true)
        #expect(fields["next"] as? String != nil)
        #expect(await rig.uninstallRequests() == [.uninstall(purgeState: true)])
        #expect(rig.questions.count == 0)
        await rig.client.disconnect()
    }

    @Test
    func `without a terminal and without yes it exits usage and changes nothing`() async {
        let rig = Rig(interactive: false)
        #expect(await rig.cli.run(["uninstall"]).exitCode == 2)
        #expect(await rig.cli.run(["uninstall", "--purge", "--json"]).output == "{\"error\":\"usage\"}\n")
        #expect(await rig.transport.requests.isEmpty)
        #expect(rig.grants.count == 0 && rig.questions.count == 0)
    }

    @Test
    func `declined confirmation makes no grant and no daemon call`() async {
        let rig = Rig(answer: false)
        let result = await rig.cli.run(["uninstall", "--json"])
        #expect(result == CLIResult(exitCode: 10, output: "{\"error\":\"declined\"}\n"))
        #expect(rig.grants.count == 0)
        #expect(await rig.transport.requests.isEmpty)
    }

    @Test
    func `bad flags exit usage before anything else`() async {
        let rig = Rig()
        for args in [["uninstall", "--bogus"], ["uninstall", "--yes", "--yes"], ["uninstall", "now"]] {
            #expect(await rig.cli.run(args).exitCode == 2)
        }
        #expect(rig.questions.count == 0 && rig.grants.count == 0)
        #expect(await rig.transport.requests.isEmpty)
    }

    @Test
    func `refused admin approval exits 4 without a daemon call`() async {
        let rig = Rig(grantFails: true)
        #expect(await rig.cli.run(["uninstall", "--yes", "--json"]) == CLIResult(exitCode: 4, output: "{\"error\":\"unauthorised\"}\n"))
        #expect(await rig.transport.requests.isEmpty)
    }

    @Test
    func `daemon refusing the right exits 4`() async {
        let rig = Rig()
        await rig.transport.override(.error(.notAuthorised(.adminRightRequired)), for: .uninstall)
        #expect(await rig.cli.run(["uninstall", "--yes"]).exitCode == 4)
        await rig.client.disconnect()
    }

    @Test
    func `unreachable daemon exits 1`() async {
        let rig = Rig()
        await rig.transport.failConnections(100)
        let result = await rig.cli.run(["uninstall", "--yes", "--json"])
        #expect(result == CLIResult(exitCode: 1, output: "{\"error\":\"daemonUnavailable\"}\n"))
        #expect(await rig.uninstallRequests().isEmpty)
    }

    @Test
    func `a failed cleanup step exits 19 naming the step`() async throws {
        let rig = Rig()
        await rig.transport.override(.error(.uninstallFailed(step: .removeDNS)), for: .uninstall)
        let json = await rig.cli.run(["uninstall", "--yes", "--json"])
        let fields = try #require(JSONSerialization.jsonObject(with: Data(json.output.utf8)) as? [String: Any])
        #expect(json.exitCode == 19)
        #expect(fields["error"] as? String == "uninstallFailed" && fields["step"] as? String == "removeDNS")
        let text = await rig.cli.run(["uninstall", "--yes"])
        #expect(text.exitCode == 19 && text.output.contains("removeDNS") && text.output.contains("again"))
        await rig.client.disconnect()
    }

    @Test
    func `a lost reply exits 20 result unknown`() async {
        let rig = Rig()
        await rig.transport.override(.error(.disconnected), for: .uninstall)
        let result = await rig.cli.run(["uninstall", "--yes", "--json"])
        #expect(result == CLIResult(exitCode: 20, output: "{\"error\":\"resultUnknown\"}\n"))
        await rig.client.disconnect()
    }

    @Test
    func `help lists the command and every exit code`() async {
        let rig = Rig()
        let help = await rig.cli.run([]).output
        #expect(help.contains("wgex uninstall [--purge] [--yes] [--json]"))
        for fragment in [
            "1 daemon unavailable",
            "2 usage",
            "4 authorisation refused",
            "19 uninstall cleanup step failed",
            "20 uninstall result unknown",
        ] {
            #expect(help.contains(fragment))
        }
    }

    @Test
    func `the confirmation prompt goes to the error sink, never the result stream`() {
        final class Box: @unchecked Sendable { var text = "" }
        let box = Box()
        let yes = CLIConsole.ask("Q?", write: { box.text += $0 }, read: { " Yes " })
        let no = CLIConsole.ask("Q?", write: { box.text += $0 }, read: { nil })
        #expect(yes && !no)
        #expect(box.text == "Q? [y/N] Q? [y/N] ")
    }
}
