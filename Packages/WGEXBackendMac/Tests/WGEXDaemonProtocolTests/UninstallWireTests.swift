// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

/// M05-T07: the uninstall request, its typed failure and the uninstall state `status` reports, on the wire.
private struct UninstallWireTests {
    @Test(arguments: [false, true])
    func `the uninstall request round-trips with the admin right's external form`(purgeState: Bool) throws {
        let envelope = Envelope(authorization: Data([7, 7, 7]), body: .uninstall(purgeState: purgeState))
        #expect(try Envelope.decode(envelope.encoded()) == envelope)
        #expect(envelope.body.kind == .uninstall)
    }

    @Test(arguments: UninstallStep.allCases)
    func `each step's failure is one fixed wire value, code and CLI row`(step: UninstallStep) throws {
        let failure = DaemonFailure.uninstall(step)
        #expect(failure.kind == .uninstallFailed && failure.code == 870)
        #expect(failure.uninstallStep == step)
        #expect(failure.wireError() == .uninstallFailed(step: step))
        let reply = Reply.error(failure.wireError())
        #expect(try WireCodec.decode(Reply.self, from: WireCodec.encode(reply)) == reply)
        let presentation = DaemonError.uninstallFailed(step: step).presentation
        #expect(presentation.cliName == "uninstallFailed" && presentation.cliExitCode == 19)
        #expect(DaemonFailure(code: .uninstallFailed).uninstallStep == nil)
    }

    @Test
    func `the step order is fixed`() {
        #expect(UninstallStep.allCases == [
            .admission, .stopTunnel, .clearIntent, .removeDNS, .removeRoutes, .emptyPolicy, .releaseReference,
            .daemonProfiles, .daemonSecrets, .onDemandBundles, .wrappingKey, .purgeState,
        ])
    }

    @Test
    func `status telemetry carries the uninstall state, and its absence decodes as none`() throws {
        var telemetry = StatusTelemetry(status: .idle)
        #expect(try WireCodec.decode(Reply.self, from: WireCodec.encode(Reply.statusTelemetry(telemetry))) == .statusTelemetry(telemetry))
        telemetry.uninstall = UninstallProgress(completed: false, purgeState: true, pendingStep: .removeRoutes)
        let decoded = try WireCodec.decode(Reply.self, from: WireCodec.encode(Reply.statusTelemetry(telemetry)))
        guard case let .statusTelemetry(value) = decoded else { throw DaemonError.malformedMessage }
        #expect(value.uninstall == telemetry.uninstall)
        #expect(value.current.uninstall == telemetry.uninstall)
    }

    @Test
    func `uninstall needs the admin right and is admitted while recovering`() async throws {
        let service = DispatcherService()
        for admin in [false, true] {
            let dispatcher = DaemonDispatcher(
                service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
                authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, hasAdminRight: { _, _ in admin }),
            )
            await dispatcher.setRecovering(true)
            let transport = try await handshaken(dispatcher)
            let reply = try await call(transport, .uninstall(purgeState: false))
            #expect(reply != .error(.recovering))
            #expect((reply == .error(.notAuthorised(.adminRightRequired))) == !admin)
        }
    }
}
