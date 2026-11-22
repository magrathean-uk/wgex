// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

internal extension OnDemandRig {
    /// Memory and the registry name the same armed profile.
    func consistent(_ expected: UUID?) async throws -> Bool {
        let memory = await controller.onDemandArmedProfileID
        let disk = try await harness.registry.armedProfile()?.registration.profile.id
        return memory == expected && disk == expected
    }

    func pendDeletion(_ id: UUID) throws {
        try harness.journal.mutate(generation: nil) { $0.pendingSecretDeletions.insert(id) }
    }

    /// Waits until `count` secret writes of the profile are decided and not yet ended (a barrier, never a spawn-then-open race).
    func queuedSecretWrites(_ count: Int, of id: UUID? = nil) async throws {
        let id = id ?? profile.id
        try await waitForCondition(timeout: .seconds(5)) { await controller.pendingSecretWrites(id) == count }
    }

    /// A manual connect through the controller's request path, with the profile's secrets.
    func connect(_ id: UUID? = nil) async throws -> Reply {
        try await controller.handle(
            .startIntent(profileID: id ?? profile.id, transport: nil, hasSecrets: true), context: context,
            secrets: ControllerHarness.bundle(),
        )
    }

    /// Restarts on the same state directory; the replacement has reconciled and replayed.
    func restart() async throws -> TunnelController {
        await controller.cancelBackgroundWork()
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        return replacement
    }
}

/// Astra H5 to H14: control commands, durable selection, secret retention and replay, each interleaved at a held await.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandPersistenceTests {
    // MARK: H5 arm against a replacement

    @Test
    func `ArmVersusReplacementAndKeyRotation: an arm commits only the registration it validated`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        let gate = PointGate { $0 == .armValidated(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        // No lane: a replacement through the control path commits while the arm is held, and the arm, which validated the
        // replaced registration, never commits (its registry compare-and-set).
        let arm = Task { try await rig.arm() }
        try await gate.reached()
        var off = rig.profile; off.onDemand = .off
        #expect(await rig.controller.installProfileCAS(off, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        gate.open()
        #expect(try await arm.value != .ok)
        await rig.idle()
        #expect(try await rig.consistent(nil))
        // A replacement that bypasses the lane (as a repair would), with new keys and policy, voids the arm's CAS.
        var edited = off; edited.onDemand = .interfaces(.ethernetOnly); edited.name = "Rotated"
        #expect(await rig.controller.installProfileCAS(edited, expectedRevision: 2, context: rig.context) == .profileRevision(3))
        let second = PointGate { $0 == .armValidated(rig.profile.id) }
        await rig.controller.setOnDemandPause(second.pause)
        let rearm = Task { try await rig.arm() }
        try await second.reached()
        var rotated = edited; rotated.onDemand = .interfaces(.wifiOnly(.anySSID)); rotated.name = "Rotated again"
        try await rig.harness.registry.installProfile(rotated, expectedRevision: 3, connectionUID: OnDemandRig.uid)
        second.open()
        #expect(try await rearm.value != .ok)
        await rig.idle()
        #expect(try await rig.consistent(nil))
    }

    // MARK: H6 ordered refresh

    @Test(arguments: InterleavingOrder.allCases)
    func `OutOfOrderProfileRefreshCannotOverwriteCommit: a refresh held after its read never undoes a newer commit`(
        order: InterleavingOrder,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        // A real refresh reads the armed selection and is held before it publishes what it read.
        let gate = PointGate { $0 == .selectionRead }
        await rig.controller.setOnDemandPause(gate.pause)
        let refresh = Task { await rig.controller.refreshArmedSelection() }
        try await gate.reached()
        switch order {
        case .inputFirst:
            // A disarm commits and publishes a newer selection while the refresh still holds the older read.
            #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
            #expect(try await rig.consistent(nil))
            gate.open(); await refresh.value
        case .continuationFirst:
            gate.open(); await refresh.value
            #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
        }
        await rig.idle()
        #expect(try await rig.consistent(nil), "the older read replaced the newer commit")
        #expect(await rig.onDemand?.armedProfileID == nil)
    }

    @Test
    func `an install that disarms while a connect is held voids the connect`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.connect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.controller.networkChanged(
            trigger: .configuration,
            underlay: UnderlayEvent(snapshot: OnDemandRig.ethernet, satisfied: true),
        )
        try await gate.reached()
        var off = rig.profile; off.onDemand = .off
        #expect(await rig.controller.installProfileCAS(off, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        gate.open(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(try await rig.consistent(nil))
    }

    // MARK: H7 command ordering

    @Test
    func `ConcurrentArmDisarmAndSameIDRearm: commands commit in order and memory follows the last commit`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate { $0 == .cleanup(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let disarm = Task { await rig.send(.disarmOnDemand(profileID: rig.profile.id)) }
        try await gate.reached()
        // No lane: the rearm commits while the older disarm is still in its cleanup, and the cleanup then defers to it.
        #expect(try await Task { try await rig.arm() }.value == .ok)
        gate.open()
        #expect(await disarm.value == .ok)
        await rig.idle()
        #expect(try await rig.consistent(rig.profile.id))
        #expect(await rig.secretsStored(), "the older disarm's cleanup deleted the rearmed profile's secrets")
        #expect(await rig.onDemand?.armedProfileID == rig.profile.id)
    }

    // MARK: H8 removal

    @Test
    func `RemoveVersusArmAndReinstall: an arm queued behind a removal finds no profile, a reinstall arms again`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate { $0 == .cleanup(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let remove = Task { await rig.send(.removeProfile(rig.profile.id, purgeSecrets: false)) }
        try await gate.reached()
        // The removal holds the profile until it ends: an arm received meanwhile is refused at its admission.
        #expect(try await Task { try await rig.arm() }.value != .ok)
        gate.open()
        #expect(await remove.value == .ok)
        await rig.idle()
        #expect(try await rig.consistent(nil))
        #expect(await !rig.secretsStored())
        try await rig.harness.registry.installProfile(rig.profile, expectedRevision: nil, connectionUID: OnDemandRig.uid)
        #expect(try await rig.arm() == .ok)
        #expect(try await rig.consistent(rig.profile.id))
    }

    // MARK: H9 cleanup ownership

    /// `releasing` holds the disarm before its release reads anything (the connect is received before the stop would have
    /// been stamped), `cleanup` just before the stop.
    @Test(arguments: [true, false])
    func `ManualOverridesSurviveOlderReleaseCleanup: a disarm's stop never stops a later manual connect`(
        beforeStamp: Bool,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let point: OnDemandPausePoint = beforeStamp ? .releasing(rig.profile.id) : .cleanup(rig.profile.id)
        let gate = PointGate { $0 == point }
        await rig.controller.setOnDemandPause(gate.pause)
        let disarm = Task { await rig.send(.disarmOnDemand(profileID: rig.profile.id)) }
        try await gate.reached()
        // No lane: the connect, received after the disarm, reserves while the disarm's cleanup is still held.
        guard case .started = try await Task(operation: { try await rig.connect() }).value else {
            Issue.record("the manual connect failed"); return
        }
        gate.open()
        #expect(await disarm.value == .ok)
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
        // A cleanup stop bound to an older claim stops nothing.
        let claim = await rig.controller.intentClaims
        await #expect(throws: OnDemandCleanupSuperseded.self) {
            try await rig.controller.testStop(
                profileID: rig.profile.id, connectionUID: OnDemandRig.uid, reason: .userRequested, boundClaim: claim &- 1,
            )
        }
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
    }

    @Test
    func `RemovalStopKeepsItsReceipt: a removal's stop never revokes a connect received while the removal waited`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        let other = try await rig.installOther()
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let gate = PointGate { $0 == .cleanup(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let remove = Task { await rig.send(.removeProfile(rig.profile.id, purgeSecrets: false)) }
        try await gate.reached()
        // Received now, so newer than the removal's stop of the armed profile; held at its check until that stop ended.
        await secure.holdNext()
        let connect = Task { try await rig.connect(other.id) }
        try await secure.latch.waited()
        gate.open()
        #expect(await remove.value == .ok)
        secure.latch.open()
        guard case .started = try await connect.value else { Issue.record("the removal's stop revoked a newer connect"); return }
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: other.id, ownerUID: OnDemandRig.uid))
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
    }

    // MARK: H10 and H11 secret retention

    @Test(arguments: InterleavingOrder.allCases)
    func `RetentionChangesDuringDeletion: a stop's deletion never removes a bundle an arm published after it`(
        order: InterleavingOrder,
    ) async throws {
        let steps = StepGate(point: .deleteSecrets)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), steps: steps)
        try await rig.arm(); await rig.idle()
        // An explicit stop outside the control lane (the controller API the cutover and update paths use), parked
        // before its journalled deletion runs.
        let stop = Task { try await rig.controller.stop(profileID: rig.profile.id, connectionUID: OnDemandRig.uid) }
        await steps.wait()
        #expect(rig.harness.journal.snapshot().pendingSecretDeletions == [rig.profile.id])
        switch order {
        case .inputFirst:
            #expect(try await rig.arm() == .ok)
            #expect(rig.harness.journal.snapshot().pendingSecretDeletions.isEmpty)
            await steps.release()
            _ = try? await stop.value
        case .continuationFirst:
            await steps.release()
            _ = try? await stop.value
            #expect(await !rig.secretsStored())
            #expect(try await rig.arm() == .ok)
        }
        await rig.idle()
        #expect(await rig.secretsStored(), "the older deletion removed the bundle the arm published")
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
    }

    @Test
    func `ArmedBundleSurvivesDeletionReplay: a journalled deletion older than the arm never runs at restart`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        // A failed explicit stop left a deletion; arming afterwards supersedes it.
        try rig.pendDeletion(rig.profile.id)
        try await rig.arm(); await rig.idle()
        #expect(rig.harness.journal.snapshot().pendingSecretDeletions.isEmpty)
        // A crash between the durable arm and the supersession leaves the deletion; replay skips the armed profile.
        try rig.pendDeletion(rig.profile.id)
        let replacement = try await rig.restart()
        #expect(await replacement.onDemandArmedProfileID == rig.profile.id)
        #expect(await rig.secretsStored())
        #expect(try DaemonJournal(directory: rig.harness.directory).snapshot().pendingSecretDeletions.isEmpty)
    }

    // MARK: H12 admission

    @Test
    func `AdmissionChangesRejectSuspendedCommands: an arm or an action admitted before recovery commits nothing`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        let gate = PointGate { $0 == .armValidated(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let arm = Task { try await rig.arm() }
        try await gate.reached()
        await rig.controller.markStartupRecovering()
        gate.open()
        let reply = try await arm.value
        #expect(reply != .ok, "an arm admitted before recovery committed")
        #expect(try await rig.consistent(nil))

        let other = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await other.arm(); await other.idle()
        let action = PointGate { $0 == .actionAdmitted(.disconnect) }
        await other.controller.setOnDemandPause(action.pause)
        try await other.controller.networkChanged(
            trigger: .configuration,
            underlay: UnderlayEvent(snapshot: OnDemandRig.wifi, satisfied: true),
        )
        try await action.reached()
        let held = await other.controller.currentGeneration
        await other.controller.markStartupRecovering()
        action.open(); await other.idle()
        #expect(await other.controller.currentGeneration == held)
        #expect(other.intent?.startedOnDemand == true)
        #expect(await other.onDemand?.decision == .paused(.recovering))
    }

    // MARK: H13 recovery publication

    @Test
    func `SupersededStartupCannotPublishArmedState: a disarm during reconciliation is never undone by its older read`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        await rig.controller.cancelBackgroundWork()
        let replacement = try rig.harness.replacementController()
        let gate = PointGate { $0 == .recoveryRead }
        await replacement.setOnDemandPause(gate.pause)
        let reconcile = Task { try await replacement.reconcileAtStartup() }
        try await gate.reached()
        #expect(await replacement.handle(.disarmOnDemand(profileID: rig.profile.id), context: rig.context, secrets: nil) == .ok)
        let log = await PhaseLog(replacement)
        gate.open()
        try await reconcile.value
        await replacement.awaitOnDemandIdle()
        // Not even transiently: no status after the disarm names the profile armed again.
        let final = await replacement.status
        try await waitForCondition(timeout: .seconds(5)) { log.statuses.withLock { $0.last } == final }
        #expect(!log.contains { $0?.armedProfileID == rig.profile.id }, "the older read was published after the disarm")
        #expect(await replacement.onDemandArmedProfileID == nil)
        #expect(try rig.record()?.armed == nil)
        #expect(await replacement.status.onDemand?.armedProfileID == nil)
    }
}
