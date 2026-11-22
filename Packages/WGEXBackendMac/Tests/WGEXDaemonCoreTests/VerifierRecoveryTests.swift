// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerifierRecoveryTests {
    @Test(arguments: [false, true])
    func `stop and settings immediately reevaluate the runtime without advancing backoff`(stop: Bool) async throws {
        let harness = try ControllerHarness(underlay: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []))
        try await harness.install()
        try harness.journal.mutate(generation: nil) { $0.intent = .init(profileID: harness.profile.id, ownerUID: 501) }
        let runtime = DaemonRuntime(clock: harness.clock)
        let composition = DaemonComposition(
            controller: harness.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
            statusJournal: StatusPublicationJournal(directory: harness.directory),
        )
        await composition.run(runtime: runtime, startListener: {}, startMonitors: {})
        #expect(await runtime.isRecovering)
        let transport = InMemoryXPCTransport(
            daemon: composition.dispatcher,
            peer: .init(uid: 501, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 10))
        if stop {
            #expect(try await call(.stopCurrent(reason: .userRequested)) == .ok)
        } else {
            await harness.controller.updateStartupUnderlay(.init(snapshot: ControllerHarness.underlay, satisfied: true))
            var settings = MacGlobalSettings.defaults; settings.allowLAN = false
            #expect(try await call(.setGlobalSettings(settings)) == .ok)
            await waitForRecovery(runtime)
            #expect(await harness.controller.status.phase == .failed(.secretsUnavailable, blockedByPolicy: true, needsSecrets: true))
        }
        await waitForRecovery(runtime)
        #expect(await !runtime.isRecovering)
        #expect(harness.clock.now == .zero)
        #expect(try await call(.statistics) != .error(.recovering))
        await runtime.stop()
    }

    @Test
    func `blocking verification failure emits reason eight and cannot claim blocked`() async throws {
        let harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) { $0.intent = .init(profileID: harness.profile.id, ownerUID: 501) }
        harness.trace.fail(at: "pf.error")
        try await harness.controller.recoveryFailed(.resolverUnavailable)
        #expect(await harness.controller.status.recoveryFailureReason == .blockingPolicyFailed)
        #expect(await harness.controller.status.protection == .unknown)
    }

    @Test
    func `fresh install remains unprotected and admin repair lifts the runtime gate`() async throws {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[1].uid = 501 }
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        let runtime = DaemonRuntime(clock: harness.clock)
        let composition = DaemonComposition(
            controller: harness.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(
                isConsoleUser: { _ in true },
                hasAdminRight: { _, _ in true },
            ),
            statusJournal: StatusPublicationJournal(directory: harness.directory),
        )
        await composition.run(runtime: runtime, startListener: {}, startMonitors: {})
        let transport = InMemoryXPCTransport(
            daemon: composition.dispatcher,
            peer: .init(uid: 501, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 10))
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(await harness.controller.status.recoveryFailureReason == .secureInstallRequired)
        #expect(!harness.trace.calls.contains("pf.error"))
        #expect(try await call(.subscribeEvents(includeLogs: false)) == .ok)
        guard case .secureInstall = try await call(.performSecureInstall) else { Issue.record("Repair refused"); return }
        await waitForRecovery(runtime)
        #expect(await !runtime.isRecovering)
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(try await call(.statistics) != .error(.recovering))
        await runtime.stop()
    }

    @Test(arguments: [false, true])
    func `profile failures without persisted protection remain unprotected and owner repair is admitted`(corrupt: Bool) async throws {
        let harness = try ControllerHarness()
        var first = harness.profile; first.macOptions.startBeforeLogin = true
        var second = try ControllerHarness.makeProfile(); second.macOptions.startBeforeLogin = true
        let repository = try DirectoryProfileRepository(directory: harness.directory)
        for profile in [first, second] {
            try repository.save(.init(registration: .init(profile: profile, revision: 1), ownerUID: 501, startBeforeLoginOverride: true))
        }
        if corrupt {
            try repository.remove(second.id)
            try harness.directory.directory("profiles").replace(first.id.uuidString + ".json", with: Data("corrupt".utf8))
        }
        let runtime = DaemonRuntime(clock: harness.clock)
        let composition = DaemonComposition(
            controller: harness.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
            statusJournal: StatusPublicationJournal(directory: harness.directory),
        )
        await composition.run(runtime: runtime, startListener: {}, startMonitors: {})
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(await harness.controller.status.recoveryFailureReason == (corrupt ? .profileUnavailable : .multipleBootProfiles))
        let transport = InMemoryXPCTransport(
            daemon: composition.dispatcher,
            peer: .init(uid: 501, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 10))
        if !corrupt {
            #expect(try await call(.installProfileCAS(first, expectedRevision: nil)) == .error(.multipleBootProfiles))
            #expect(try await call(.setStartBeforeLoginIntent(profileID: second.id, enabled: false)) == .ok)
        } else {
            var repaired = first; repaired.macOptions.startBeforeLogin = false
            #expect(try await call(.installProfileCAS(repaired, expectedRevision: 1)) == .profileRevision(1))
            #expect(try await call(.removeProfile(first.id, purgeSecrets: false)) == .ok)
        }
        await waitForRecovery(runtime)
        #expect(await !runtime.isRecovering)
        await runtime.stop()
    }

    @Test
    func `runtime queues one retry during an attempt and never reconciles after success`() async {
        let runtime = DaemonRuntime(clock: HostClock()), gate = StepGate(point: .inspectReality)
        let count = Mutex(0)
        let task = Task {
            await runtime.run(ports: .init(startListener: {}, setRecovering: { _ in }, reconcile: {
                let first = count.withLock { $0 += 1; return $0 == 1 }
                if first {
                    try await gate.before(.inspectReality, generation: .initial); throw DaemonFailure.startup(.resolverUnavailable)
                }
            }, startMonitors: {}, block: { _ in }, shouldRetry: { true }, shutdown: {}))
        }
        await gate.wait()
        await runtime.retryNow(); await runtime.retryNow()
        await gate.release(); await task.value
        #expect(count.withLock { $0 } == 2)
        await waitForRecovery(runtime)
        #expect(await !runtime.isRecovering)
        await runtime.retryNow()
        #expect(count.withLock { $0 } == 2)
        await runtime.stop()
    }
}

private func waitForRecovery(_ runtime: DaemonRuntime) async {
    let deadline = ContinuousClock.now + .seconds(5)
    while await runtime.isRecovering, ContinuousClock.now < deadline, !Task.isCancelled {
        await Task.yield()
    }
}
