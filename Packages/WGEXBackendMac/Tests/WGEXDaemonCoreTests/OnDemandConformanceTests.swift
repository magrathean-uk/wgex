// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

internal enum HandoffCommand: CaseIterable, Sendable {
    case start, arm, cutover
}

internal enum BootOrder: CaseIterable, Sendable {
    /// The newer disable commits while the older enable is held, then the enable resumes.
    case disableFirst
    /// The older enable resumes and commits while the newer disable is held before its commit.
    case enableFirst
    /// The profile is removed and installed again while the enable is held.
    case reinstalled
}

/// DEC-012 conformance, round 8 (REV round 7 required changes 1 to 4): the app-secret handoff runs under its command's
/// admission, every stop reservation is admission-aware, start-before-login commits land in receipt order per profile and
/// registration incarnation, and a cutover revokes the enables admitted before it.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandConformanceTests {
    /// Required change 1: a start, an arm or a cutover sent without secrets waits on a held `provideSecrets`; a newer stop or
    /// disarm of the profile completes; the app then supplies the bundle, and the older command neither starts, arms nor
    /// arms a trial, because the callback continues under the admission it was received with.
    @Test(arguments: HandoffCommand.allCases)
    func `AppSecretHandoffKeepsItsAdmission: a held provideSecrets resumes after a newer stop or disarm and changes nothing`(
        command: HandoffCommand,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let id = rig.profile.id, held = Latch()
        let dispatcher = DaemonDispatcher(
            service: rig.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }, isAppClient: { _ in true }),
            clock: .init(now: { Double(rig.harness.clock.now.components.seconds) }, sleep: { try await rig.harness.clock.sleep(for: $0) }),
        )
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: .init(
            uid: OnDemandRig.uid, pid: 11, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied,
        ))
        try await app.connect(callbacks: .init(provideSecrets: { _ in
            await held.wait()
            let wire = try ControllerHarness.bundle().wireBytes()
            return wire.withUnsafeBytes { Data($0) }
        }))
        _ = try await Self.call(app, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await Self.call(app, .subscribeEvents(includeLogs: false))
        let request: Request = switch command {
        case .start: .startIntent(profileID: id, transport: nil, hasSecrets: false)
        case .arm: .armOnDemand(profileID: id, hasSecrets: false)
        case .cutover: .startCutover(profileID: id, confirmWithin: 600, hasSecrets: false)
        }
        let pending = Task { try await Self.call(app, request) }
        try await held.waited()
        let newer: Request = command == .arm ? .disarmOnDemand(profileID: id) : .stop(profileID: id, reason: .userRequested)
        #expect(await rig.send(newer) == .ok, "the newer command waited for the app's secrets handoff")
        let engines = rig.harness.trace.calls.filter { $0 == "engine.create" }.count
        held.open()
        let reply = try await pending.value
        await rig.idle()
        #expect(reply != .ok, "an arm received before a newer disarm armed after it")
        if case .started = reply {
            Issue.record("a start or cutover received before a newer stop started after it")
        }
        #expect(rig.intent == nil)
        #expect(rig.harness.journal.snapshot().cutover == nil, "a cutover received before a newer stop armed its trial")
        #expect(try await !rig.armedInRegistry())
        #expect(rig.harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
        await app.invalidate()
    }

    /// Required change 2: a stop of any reason (the retained-intent ones included: update, failure, logout, shutdown,
    /// takeover) held after its owner lookup never stops a manual connect received after it.
    @Test(arguments: StopReason.allCases)
    func `OlderStopNeverStopsNewerStart: a stop held before its reservation never stops a newer manual connect`(
        reason: StopReason,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let gate = PointGate { $0 == .stopping(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let stop = Task { await rig.send(.stop(profileID: rig.profile.id, reason: reason)) }
        try await gate.reached()
        guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        let generation = await rig.controller.currentGeneration
        gate.open()
        #expect(await stop.value != .ok, "a stop received before the connect reported stopping it")
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid), "the older stop ended the intent")
        #expect(await rig.controller.currentGeneration == generation, "the older stop reserved after the newer start")
        #expect(await rig.controller.status.phase == .active(generation))
    }

    /// Required change 3: an enable held at its secret publication, then a newer disable, or a removal and reinstall of the
    /// profile; in every completion order start-before-login ends disabled.
    @Test(arguments: BootOrder.allCases)
    func `BootIntentCommitsInReceiptOrder: an older enable never leaves boot enabled after a newer disable or reinstall`(
        order: BootOrder,
    ) async throws {
        let rig = try await OnDemandRig(.off)
        let id = rig.profile.id
        let publishing = PointGate { $0 == .publishing(id) }
        let commit = PointGate { order == .enableFirst && $0 == .bootCommit(id) }
        await rig.controller.setOnDemandPause { point in
            await publishing.pause(point); await commit.pause(point)
        }
        let enable = Task {
            try await rig.controller.handle(
                .setStartBeforeLoginIntent(profileID: id, enabled: true), context: rig.context, secrets: ControllerHarness.bundle(),
            )
        }
        try await publishing.reached()
        switch order {
        case .disableFirst:
            #expect(await rig.send(.setStartBeforeLoginIntent(profileID: id, enabled: false)) == .ok)
            publishing.open()
            #expect(try await enable.value != .ok, "an older enable committed after a newer disable")
        case .enableFirst:
            let disable = Task { await rig.send(.setStartBeforeLoginIntent(profileID: id, enabled: false)) }
            try await commit.reached()
            publishing.open()
            #expect(try await enable.value == .ok)
            commit.open()
            #expect(await disable.value == .ok)
        case .reinstalled:
            #expect(await rig.send(.removeProfile(id, purgeSecrets: false)) == .ok)
            #expect(await rig.controller.installProfileCAS(rig.profile, expectedRevision: nil, context: rig.context) == .profileRevision(1))
            publishing.open()
            #expect(try await enable.value != .ok, "an enable of the removed registration landed on its reinstall")
        }
        #expect(try await rig.harness.registry.bootIntent() == nil, "start-before-login is enabled against receipt order")
    }

    /// Required change 4: an enable held at its publication through a trial of its profile, the trial's abort and its
    /// rollback's boot-intent restore never enables start-before-login afterwards.
    @Test
    func `CutoverRevokesHeldEnable: an enable held through a trial, its abort and the restore leaves boot disabled`() async throws {
        let rig = try await OnDemandRig(.off)
        let id = rig.profile.id
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: id)
        let publishing = PointGate { $0 == .publishing(id) }
        await rig.controller.setOnDemandPause(publishing.pause)
        let enable = Task {
            try await rig.controller.handle(
                .setStartBeforeLoginIntent(profileID: id, enabled: true), context: rig.context, secrets: ControllerHarness.bundle(),
            )
        }
        try await publishing.reached()
        _ = try await rig.controller.startCutover(profileID: id, connectionUID: OnDemandRig.uid, confirmWithin: 600)
        #expect(await rig.controller.cutoverIsArmed)
        try await rig.controller.abortCutover(connectionUID: OnDemandRig.uid)
        #expect(await !rig.controller.cutoverIsArmed)
        publishing.open()
        #expect(try await enable.value != .ok, "an enable admitted before the trial committed after its rollback")
        #expect(try await rig.harness.registry.bootIntent() == nil, "the rollback's restore was undone by an older enable")
    }

    private static func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }
}
