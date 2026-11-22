// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// REV round 8 required changes 1 (H7) and 2 (H10): an explicit disarm stops a profile an older manual start committed and
/// still holds, and overlapping purge replays never delete secrets a reinstall published.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandRound9Tests {
    /// Change 1, post-reservation: the on-demand tunnel is up; a manual connect reserves and is held in its secret
    /// publication (committed, still holding the profile); a newer disarm then stops it (ADR-030 section 6 rule 2), and the
    /// connect, released, never brings the tunnel back.
    @Test
    func `DisarmStopsCommittedManualStart: a disarm after a manual connect reserved stops it and the intent stays cleared`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let gate = PointGate { $0 == .publishing(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let connect = Task { try await rig.connect() }
        try await gate.reached()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid), "the connect did not reserve")
        let disarm = Task { await rig.send(.disarmOnDemand(profileID: rig.profile.id)) }
        let stopped = await (try? waitForCondition(timeout: .seconds(5)) { rig.intent == nil }) != nil
        gate.open()
        #expect(stopped, "the disarm deferred to an older manual connect that had already reserved")
        #expect(await disarm.value == .ok)
        _ = try? await connect.value
        await rig.idle()
        #expect(rig.intent == nil, "the older manual connect's intent survived the newer disarm")
        #expect(try await rig.consistent(nil))
    }

    /// Change 1, held callback: a manual connect sent without secrets reserves, finds no bundle and waits on the app's held
    /// `provideSecrets`; a newer disarm stops the intent; the app then supplies the bundle and nothing starts.
    @Test
    func `DisarmStopsManualStartInHandoff: a disarm during a manual connect's secrets callback stops it for good`() async throws {
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
        let pending = Task { try await Self.call(app, .startIntent(profileID: id, transport: nil, hasSecrets: false)) }
        try await held.waited()
        let intentInCallback = rig.intent
        #expect(await rig.send(.disarmOnDemand(profileID: id)) == .ok)
        let intentAfterDisarm = rig.intent
        let engines = rig.harness.trace.calls.filter { $0 == "engine.create" }.count
        held.open()
        let reply = try await pending.value
        await rig.idle()
        #expect(intentInCallback != nil, "the connect had not reserved before its callback")
        #expect(intentAfterDisarm == nil, "the disarm deferred to a manual connect held in its secrets callback")
        if case .started = reply {
            Issue.record("a manual connect received before a newer disarm started after it")
        }
        #expect(rig.intent == nil)
        #expect(rig.harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
        await app.invalidate()
    }

    /// Change 1 follow-on (survivor F1, now that a disarm never defers to a hold): the profile is armed but not connected; a
    /// manual connect is held at its secure-install check; a newer disarm supersedes it, so its hold no longer retains the
    /// profile's secrets and the disarm deletes the armed retention before the connect is released.
    @Test
    func `DisarmDropsSupersededHold: a disarm deletes the armed secrets while a superseded manual connect is held`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi, secureInstall: secure)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.secretsStored())
        await secure.holdNext()
        let connect = Task { try await rig.connect() }
        try await secure.latch.waited()
        let reply = await rig.send(.disarmOnDemand(profileID: rig.profile.id))
        let storedWhileHeld = await rig.secretsStored()
        secure.latch.open()
        #expect(reply == .ok)
        #expect(!storedWhileHeld, "a superseded manual connect's hold kept the disarmed profile's secrets")
        if case .started = try await connect.value {
            Issue.record("a manual connect received before the disarm started after it")
        }
        await rig.idle()
        #expect(rig.intent == nil)
        #expect(await !rig.secretsStored())
        #expect(try await rig.consistent(nil))
    }

    /// Change 2: a crash left a purge tombstone with its registration and secrets. The first startup replay is held in the
    /// deletion past its watchdog; a second replay runs its own deletion of the same tombstone, which finishes first and
    /// removes the tombstone. A reinstall then publishes fresh secrets; the late first deletion must not delete them.
    @Test
    func `OverlappingPurgeReplaysKeepReinstall: a late first deletion never deletes secrets a reinstall published`() async throws {
        let rig = try await OnDemandRig(.off)
        let other = try await rig.installOther()
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        let repository = try DirectoryProfileRepository(directory: rig.harness.directory)
        let loaded = try repository.load(other.id)
        let record = try #require(loaded)
        try repository.stagePurge(RegisteredProfile(registration: record.registration, ownerUID: record.ownerUID))
        let gates = PurgeGates()
        await rig.harness.registry.setPurgePause(gates.pause)
        let firstReplay = Task { try await rig.controller.reconcileAtStartup() }
        try await gates.first.waited()
        try await waitForCondition { rig.harness.clock.pendingSleeps.contains(.seconds(60)) }
        rig.harness.clock.advance(.seconds(60))
        _ = try? await firstReplay.value
        let secondReplay = Task { try await rig.controller.reconcileAtStartup() }
        try await gates.second.waited()
        gates.second.open()
        try await waitForCondition { (try? repository.pendingPurges().isEmpty) == true }
        let reinstalled = Shared(false)
        let reinstall = Task {
            try await rig.harness.registry.installProfile(other, expectedRevision: nil, connectionUID: OnDemandRig.uid)
            // The reinstalled bundle is claimed (start-before-login), so a replay's startup sweep of unclaimed bundles
            // (M05-T02) keeps it; only a late purge deletion could remove it.
            try await rig.harness.registry.setStartBeforeLogin(other.id, enabled: true, connectionUID: OnDemandRig.uid)
            try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
            reinstalled.withLock { $0 = true }
        }
        // Barrier: the reinstall either waits for the held first deletion or has already published.
        try await waitForCondition {
            await rig.harness.registry.installsAwaitingPurge(of: other.id) == 1 || reinstalled.withLock { $0 }
        }
        #expect(!reinstalled.withLock { $0 }, "the reinstall published while the first deletion was still running")
        gates.first.open()
        try await reinstall.value
        try await waitForCondition { await rig.harness.registry.purgeDeletionsRunning(of: other.id) == 0 }
        _ = try? await secondReplay.value
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == OnDemandRig.uid)
        #expect(await rig.secretsStored(other.id), "a late purge deletion deleted the reinstalled profile's secrets")
    }

    /// Change 2, install first: a crash left a purge tombstone with its registration and secrets. A reinstall starts that
    /// tombstone's deletion itself and is held in it; a startup replay then starts its own deletion of the same tombstone,
    /// also held. The reinstall's deletion finishes first and removes the tombstone; the reinstall must keep waiting for the
    /// replay's deletion, and the fresh secrets it publishes afterwards must survive.
    @Test
    func `InstallFirstPurgeReplayKeepsReinstall: a reinstall waits for a replay deletion started during its own`() async throws {
        let rig = try await OnDemandRig(.off)
        let other = try await rig.installOther()
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        let repository = try DirectoryProfileRepository(directory: rig.harness.directory)
        let loaded = try repository.load(other.id)
        let record = try #require(loaded)
        try repository.stagePurge(RegisteredProfile(registration: record.registration, ownerUID: record.ownerUID))
        let gates = PurgeGates()
        await rig.harness.registry.setPurgePause(gates.pause)
        let reinstalled = Shared(false)
        let reinstall = Task {
            try await rig.harness.registry.installProfile(other, expectedRevision: nil, connectionUID: OnDemandRig.uid)
            // The reinstalled bundle is claimed (start-before-login), so a replay's startup sweep of unclaimed bundles
            // (M05-T02) keeps it; only a late purge deletion could remove it.
            try await rig.harness.registry.setStartBeforeLogin(other.id, enabled: true, connectionUID: OnDemandRig.uid)
            try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
            reinstalled.withLock { $0 = true }
        }
        try await gates.first.waited()
        #expect(await rig.harness.registry.purgeDeletionsAwaited(of: other.id) == 1)
        let replay = Task { try await rig.controller.reconcileAtStartup() }
        try await gates.second.waited()
        gates.first.open()
        try await waitForCondition { await rig.harness.registry.purgeDeletionsRunning(of: other.id) == 1 }
        #expect((try? repository.pendingPurges().isEmpty) == true)
        // Barrier: the reinstall either waits for the replay's held deletion (its second pass) or has already published.
        try await waitForCondition {
            await rig.harness.registry.purgeDeletionsAwaited(of: other.id) == 2 || reinstalled.withLock { $0 }
        }
        #expect(!reinstalled.withLock { $0 }, "the reinstall published while the replay's deletion was still running")
        #expect(await rig.harness.registry.installsAwaitingPurge(of: other.id) == 1)
        gates.second.open()
        try await reinstall.value
        _ = try? await replay.value
        #expect(await rig.harness.registry.purgeDeletionsRunning(of: other.id) == 0)
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == OnDemandRig.uid)
        #expect(await rig.secretsStored(other.id), "a late replay deletion deleted the reinstalled profile's secrets")
    }

    private static func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }
}
