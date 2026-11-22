// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5CutoverHandoffTests {
    @Test
    func `D9 dispatcher handoff expires after five seconds without arming a trial`() async throws {
        let h = try ControllerHarness(); try await h.install()
        let codes = Mutex<[DaemonFailure.Code]>([])
        let dispatcher = DaemonDispatcher(
            service: h.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
            clock: .init(now: { Double(h.clock.now.components.seconds) }, sleep: { try await h.clock.sleep(for: $0) }),
            secretFailure: { failure in codes.withLock { $0.append(failure.kind) } },
        )
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501, pid: 11, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: { _ in
            try await h.clock.sleep(for: .seconds(60)); return Data()
        }))
        _ = try await call(app, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        let trial = Task { try await call(app, .startCutover(profileID: h.profile.id, confirmWithin: 60, hasSecrets: false)) }
        try await waitForCondition { h.clock.pendingSleeps.contains(.seconds(5)) && h.clock.pendingSleeps.contains(.seconds(60)) }
        h.clock.advance(.seconds(5))
        #expect(try await trial.value == .error(.tunnel(.timedOut)))
        #expect(codes.withLock { $0 } == [.tunnelTimedOut])
        #expect(h.journal.snapshot().intent == nil && h.journal.snapshot().cutover == nil)
        #expect(!h.trace.calls.contains("engine.create"))
        await app.invalidate()
    }

    @Test
    func `D9 secure install refusal happens before an app is asked for trial secrets`() async throws {
        let h = try ControllerHarness(secureInstall: UnavailableSecureInstall()); try await h.install()
        let dispatcher = DaemonDispatcher(
            service: h.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let requested = HostTrace()
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501,
            pid: 11,
            auditSessionID: 1,
            codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: { _ in try requested.record("provideSecrets"); return Data() }))
        _ = try await call(app, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        let reply = try await call(app, .startCutover(profileID: h.profile.id, confirmWithin: 60, hasSecrets: false))
        #expect(reply == .error(.secureInstallRequired))
        #expect(requested.calls.isEmpty)
        #expect(h.journal.snapshot().cutover == nil && h.journal.snapshot().intent == nil)
    }

    @Test(arguments: [true, false], [uid_t(501), 502])
    func `D9 idle CLI trial requests fixture secrets only from an authenticated owner app`(
        _ appRunning: Bool,
        _ appUID: uid_t,
    ) async throws {
        let h = try ControllerHarness(); try await h.install()
        let dispatcher = DaemonDispatcher(
            service: h.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let requested = HostTrace()
        if appRunning {
            let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
                uid: appUID,
                pid: 11,
                auditSessionID: 1,
                codeSigningVerdict: .requirementSatisfied,
            ))
            try await app.connect(callbacks: .init(provideSecrets: { id in
                guard id == h.profile.id else { throw DaemonError.secretsUnavailable }
                try requested.record("provideSecrets")
                let wire = try ControllerHarness.bundle().wireBytes()
                return wire.withUnsafeBytes { Data($0) }
            }))
            _ = try await call(app, .hello(clientVersion: "test", clientBuild: 10))
            _ = try await call(app, .subscribeEvents(includeLogs: false))
        }
        let cli = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: 501,
            pid: 12,
            auditSessionID: 1,
            codeSigningVerdict: .requirementSatisfied,
        ))
        try await cli.connect(callbacks: .init())
        _ = try await call(cli, .hello(clientVersion: "test", clientBuild: 10))
        #expect(h.journal.snapshot().intent == nil)
        let reply = try await call(cli, .startCutover(profileID: h.profile.id, confirmWithin: 60, hasSecrets: false))
        if appRunning, appUID == 501 {
            guard case .started = reply else { Issue.record("Owner app did not supply the trial"); return }
            #expect(requested.calls == ["provideSecrets"])
            #expect(h.journal.snapshot().cutover != nil)
            try await h.controller.abortCutover(connectionUID: 501)
        } else {
            #expect(reply == .error(.secretsUnavailable))
            #expect(requested.calls.isEmpty)
            #expect(h.journal.snapshot().intent == nil && h.journal.snapshot().cutover == nil)
        }
        await h.controller.cancelBackgroundWork()
    }

    private func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }
}
