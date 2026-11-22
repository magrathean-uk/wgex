// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Admission hazards (DEC-012, round 7): a stop supersedes older starts and arms of its profile at its own admission and
/// waits for nothing they hold; a stop of another profile waits for nothing either; an older command never commits after a
/// newer one; a purge holds nothing while it deletes secrets.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandRevocationTests {
    /// Round 6, required change 1: with A active, a purge of C is held in its secret deletion and a start of B is held at
    /// its secure-install check; a stop of A completes, and B, received before the stop ended the intent, never reserves.
    @Test(arguments: StartPath.allCases)
    func `StopNotStarvedByOtherProfileStart: a stop of A completes while purge C and start B are held, and B never reserves`(
        path: StartPath,
    ) async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        let profileB = try await rig.installOther(), profileC = try await rig.installOther()
        guard case .started = try await rig.connect() else { Issue.record("the manual connect of A failed"); return }
        let purge = Latch()
        await rig.harness.registry.setPurgePause { await purge.wait() }
        let purging = Task { await rig.send(.removeProfile(profileC.id, purgeSecrets: true)) }
        try await purge.waited()
        await secure.holdNext()
        let start = Task<Bool, Never> {
            switch path {
            case .request:
                guard case .started = try? await rig.connect(profileB.id) else { return false }
                return true
            case .api:
                return await (try? rig.controller.start(
                    profileID: profileB.id, connectionUID: OnDemandRig.uid, secrets: ControllerHarness.bundle(),
                )) != nil
            }
        }
        try await secure.latch.waited()
        let engines = rig.harness.trace.calls.filter { $0 == "engine.create" }.count
        let stopped = Shared(false)
        let stop = Task {
            let reply = await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested))
            stopped.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { stopped.withLock { $0 } }) != nil
        let generation = await rig.controller.currentGeneration
        secure.latch.open()
        #expect(completed, "the stop of A waited behind a start of B or a purge of C")
        #expect(await stop.value == .ok)
        #expect(await start.value == false, "a start received before the stop reserved after it")
        #expect(await rig.controller.currentGeneration == generation)
        #expect(rig.intent == nil)
        #expect(await rig.controller.status.phase == .idle)
        #expect(rig.harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
        purge.open()
        #expect(await purging.value == .ok)
        #expect(try await rig.harness.registry.ownerUID(for: profileC.id) == nil)
    }

    /// Round 6, required change 2 (H7): an arm held at its secure-install check, then a newer manual connect of its profile or
    /// a newer arm of another profile completes; the older arm never commits, and the newer state survives.
    @Test(arguments: [false, true])
    func `OlderArmNeverOvertakesNewerControl: a held arm loses to a newer manual connect or a newer arm of another profile`(
        newerArm: Bool,
    ) async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        let other = try await rig.installOther(.interfaces(.ethernetOnly))
        await secure.holdNext()
        let arm = Task { try await rig.arm() }
        try await secure.latch.waited()
        if newerArm {
            #expect(try await rig.arm(other.id) == .ok)
        } else {
            guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        }
        secure.latch.open()
        #expect(try await arm.value != .ok, "the older arm committed after a newer command")
        await rig.idle()
        if newerArm {
            #expect(try await rig.consistent(other.id), "the older arm took the selection back")
        } else {
            #expect(try await rig.consistent(nil), "the older arm re-armed the manually connected profile")
            #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
            #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
        }
    }

    /// Round 6, required change 3 (H12): a cutover with a supplied bundle is held at its first check; a stop of its profile
    /// completes; the cutover then arms no trial and starts nothing, because it runs under the admission it was received with.
    @Test
    func `CutoverKeepsItsReceipt: a cutover held at its first check arms no trial and starts nothing after a newer stop`() async throws {
        let secure = HeldSecureInstall()
        let harness = try ControllerHarness(secureInstall: secure)
        try await harness.install()
        let id = harness.profile.id
        await secure.holdNext()
        let cutover = Task {
            try await harness.controller.startCutover(
                profileID: id, connectionUID: ControllerHarness.uid, confirmWithin: 60, secrets: ControllerHarness.bundle(),
            )
        }
        try await secure.latch.waited()
        try await harness.controller.stop(profileID: id, connectionUID: ControllerHarness.uid)
        let generation = await harness.controller.currentGeneration
        secure.latch.open()
        await #expect(throws: (any Error).self, "the cutover started after a newer stop") { try await cutover.value }
        #expect(harness.journal.snapshot().cutover == nil, "the cutover armed its trial after a newer stop")
        #expect(await harness.controller.currentGeneration == generation)
        #expect(await harness.controller.status.phase == .idle)
        #expect(!harness.trace.calls.contains("engine.create"))
    }

    /// Commit order: a disarm held before its durable disarm, then a newer arm of the profile commits; the older disarm's
    /// write is skipped, so the newer arm survives (the disarm is ordered before it, as received).
    @Test
    func `OlderDisarmNeverUndoesNewerArm: a disarm held before its write leaves a newer arm of the profile armed`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate { $0 == .disarming(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let disarm = Task { await rig.send(.disarmOnDemand(profileID: rig.profile.id)) }
        try await gate.reached()
        #expect(try await rig.arm() == .ok)
        gate.open()
        #expect(await disarm.value == .ok)
        await rig.idle()
        #expect(try await rig.consistent(rig.profile.id), "an older disarm undid a newer arm")
        #expect(await rig.secretsStored())
    }

    /// Reservation order: a manual disconnect held before its override, then a newer manual connect of the profile reserves;
    /// the older stop never stops it.
    @Test
    func `OlderStopNeverStopsNewerConnect: a manual stop held before its override never stops a newer manual connect`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        let gate = PointGate { $0 == .disarming(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let stop = Task { await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested)) }
        try await gate.reached()
        guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        let generation = await rig.controller.currentGeneration
        gate.open()
        #expect(await stop.value != .ok, "a stop received before the connect reported stopping it")
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid), "the older stop stopped it")
        #expect(await rig.controller.currentGeneration == generation)
        #expect(try await rig.consistent(nil))
    }

    /// ADR-030 section 6 hold: a release stop of a profile a manual connect holds is deferred, so a command received after the
    /// connect (here the release replay) never stops the profile before the connect claims it.
    @Test
    func `ReleaseStopDefersToManualCommand: a replay's owed stop waits for the manual connect holding the profile`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        try await rig.controller.testRecordOwedStop(rig.profile.id)
        #expect(try await rig.harness.registry.pendingReleases() == [OnDemandRelease(profileID: rig.profile.id, stopsIntent: true)])
        let gate = PointGate { $0 == .selectionRead }
        await rig.controller.setOnDemandPause(gate.pause)
        let connect = Task { try await rig.connect() }
        try await gate.reached()
        await rig.controller.scheduleReleaseReplay()
        await rig.controller.awaitOnDemandIdle()
        #expect(rig.intent?.startedOnDemand == true, "the replay stopped a profile a manual connect holds")
        gate.open()
        guard case .started = try await connect.value else { Issue.record("the manual connect lost to the replay"); return }
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
    }

    /// Two-phase purge: the tombstone and the removal commit at once; the secret deletion holds nothing, and a reinstall of the
    /// purged id waits for it, so the deletion never removes what comes with the reinstall.
    @Test
    func `PurgeIsTwoPhase: a purge held in its deletion blocks no registry write, and a reinstall of the id waits for it`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther()
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        let purge = Latch()
        await rig.harness.registry.setPurgePause { await purge.wait() }
        let removal = Task { await rig.send(.removeProfile(other.id, purgeSecrets: true)) }
        try await purge.waited()
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == nil, "the removal did not commit before its deletion")
        #expect(try await rig.arm() == .ok, "a registry write waited behind a purge's secret deletion")
        let reinstalled = Shared(false)
        let reinstall = Task {
            try await rig.harness.registry.installProfile(other, expectedRevision: nil, connectionUID: OnDemandRig.uid)
            try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
            reinstalled.withLock { $0 = true }
        }
        try? await Task.sleep(for: .milliseconds(300)) // Room for a reinstall that does not wait to finish first.
        #expect(!reinstalled.withLock { $0 }, "a reinstall of the purged id finished during its purge")
        purge.open()
        try await reinstall.value
        #expect(await removal.value == .ok)
        #expect(await rig.secretsStored(other.id), "the purge deleted the secrets of the reinstalled profile")
    }

    @Test
    func `StopNotStarvedByArmCheck: a stop completes while an arm's secure-install check is held, and the arm is revoked`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        await secure.holdNext()
        let arm = Task { try await rig.arm() }
        try await secure.latch.waited()
        let stopped = Shared(false)
        let stop = Task {
            let reply = await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested))
            stopped.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { stopped.withLock { $0 } }) != nil
        secure.latch.open()
        #expect(completed, "the stop waited behind the arm's held secure-install check")
        #expect(await stop.value == .ok)
        #expect(try await arm.value != .ok, "an arm received before the stop armed after it")
        await rig.idle()
        #expect(try await !rig.armedInRegistry())
        #expect(rig.intent == nil, "the arm received before the stop reconnected after it")
    }

    /// A stop of another profile supersedes nothing; nothing it waits for is held by the start or the arm.
    @Test(arguments: HeldCommand.allCases)
    func `StopNotStarvedByStartChecks: a stop of another profile completes while a start's or an arm's check is held`(
        command: HeldCommand,
    ) async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        let other = try await rig.installOther()
        guard case .started = try await rig.connect(other.id) else { Issue.record("the manual connect failed"); return }
        await secure.holdNext()
        let held = Task<Bool, Never> {
            switch command {
            case .start: guard case .started = try? await rig.connect() else { return false }
            case .arm: guard await (try? rig.arm()) == .ok else { return false }
            }
            return true
        }
        try await secure.latch.waited()
        let stopped = Shared(false)
        let stop = Task {
            let reply = await rig.send(.stop(profileID: other.id, reason: .userRequested))
            stopped.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { stopped.withLock { $0 } }) != nil
        secure.latch.open()
        #expect(completed, "the stop of another profile waited behind a held secure-install check")
        #expect(await stop.value == .ok)
        // The start was received before the stop ended the intent, so it is revoked; the arm commutes with the stop.
        #expect(await held.value == (command == .arm))
    }

    /// Found in the round-6 audit: with the checks before the lane, an older start can reach its reservation after a newer one.
    @Test
    func `StartNotOvertakenByOlderStart: an older start whose check finished last never replaces a newer start`() async throws {
        let secure = HeldSecureInstall()
        let harness = try ControllerHarness(secureInstall: secure)
        try await harness.install()
        let id = harness.profile.id
        await secure.holdNext()
        let older = Task {
            try await harness.controller.start(profileID: id, connectionUID: ControllerHarness.uid, secrets: ControllerHarness.bundle())
        }
        try await secure.latch.waited()
        let newer = try await harness.controller.start(
            profileID: id, connectionUID: ControllerHarness.uid, secrets: ControllerHarness.bundle(),
        )
        let engines = harness.trace.calls.filter { $0 == "engine.create" }.count
        secure.latch.open()
        await #expect(throws: (any Error).self, "the older start reserved after the newer one") { try await older.value }
        #expect(await harness.controller.currentGeneration == newer)
        #expect(await harness.controller.status.phase == .active(newer))
        #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
    }
}
