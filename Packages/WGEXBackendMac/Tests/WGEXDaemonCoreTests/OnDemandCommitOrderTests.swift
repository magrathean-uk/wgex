// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Holds the first purge deletion on `first` and the second on `second`, so the two can finish in either order.
internal final class PurgeGates: Sendable {
    internal let first = Latch(), second = Latch()
    private let calls = Shared(0)

    internal var pause: @Sendable () async -> Void {
        { [first, second, calls] in
            let call = calls.withLock { count in
                count += 1
                return count
            }
            if call == 1 {
                await first.wait()
            } else if call == 2 {
                await second.wait()
            }
        }
    }
}

/// A repository that lists the staged purges with `first` ahead of the others, so a replay's order is fixed.
private final class PurgeOrderRepository: ProfileRepository {
    let base: any ProfileRepository
    let first: Shared<UUID?>

    init(base: any ProfileRepository, first: Shared<UUID?>) {
        self.base = base
        self.first = first
    }

    func pendingPurges() throws -> [RegisteredProfile] {
        let leading = first.withLock { $0 }
        let staged = try base.pendingPurges()
        return staged.filter { $0.registration.profile.id == leading } + staged.filter { $0.registration.profile.id != leading }
    }

    func load(_ id: UUID) throws -> RegisteredProfile? {
        try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        try base.save(profile)
    }

    func remove(_ id: UUID) throws {
        try base.remove(id)
    }

    func all() throws -> [RegisteredProfile] {
        try base.all()
    }

    func recordForRepair(_ id: UUID) throws -> RegisteredProfile? {
        try base.recordForRepair(id)
    }

    func legacyRemovalOwner(_ id: UUID, after failure: any Error) throws -> UInt32? {
        try base.legacyRemovalOwner(id, after: failure)
    }

    func otherRecords(excluding id: UUID) throws -> [RegisteredProfile] {
        try base.otherRecords(excluding: id)
    }

    func stagePurge(_ record: RegisteredProfile) throws {
        try base.stagePurge(record)
    }

    func finishPurge(_ id: UUID) throws {
        try base.finishPurge(id)
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        try base.loadOnDemandRecord()
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        try base.saveOnDemandRecord(record)
    }
}

/// DEC-012 conformance, round 8 (REV round 7 required changes 5 and 6): a dead admission never commits, registration
/// writes land in receipt order, and each fence the round-7 mutation pass left untested has its own schedule.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandCommitOrderTests {
    /// Required change 5: in recovery, a removal's repair expires while its purge deletion is held; an install of the id
    /// then waits for that purge past its own watchdog; the deletion completes late. The install's repair is dead by then,
    /// so it writes no registration.
    @Test
    func `ExpiredRepairNeverCommits: an install that outlives its watchdog waiting on a purge writes no registration`() async throws {
        let rig = try await OnDemandRig(.off)
        let other = try await rig.installOther()
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        await rig.controller.testEnterRecovery()
        let purge = Latch()
        await rig.harness.registry.setPurgePause { await purge.wait() }
        let removal = Task { await rig.send(.removeProfile(other.id, purgeSecrets: true)) }
        try await purge.waited()
        try await Self.expireOperation(rig)
        #expect(await removal.value != .ok, "the removal's repair did not expire")
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == nil)
        let install = Task { await rig.controller.installProfileCAS(other, expectedRevision: nil, context: rig.context) }
        try await waitForCondition { await rig.harness.registry.installsAwaitingPurge(of: other.id) == 1 }
        try await Self.expireOperation(rig)
        #expect(await install.value != .profileRevision(1), "the install's repair did not expire")
        purge.open()
        // The install commits, or is refused, in the registry turn that ends its wait.
        try await waitForCondition { await rig.harness.registry.installsAwaitingPurge(of: other.id) == 0 }
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == nil, "an expired install wrote the registration")
    }

    /// Audit of change 3 (install and removal scopes): an install that waits for a crash's leftover purge is overtaken by a
    /// removal of the id received after it; it reports a revision conflict instead of resurrecting the profile.
    @Test
    func `OlderInstallNeverUndoesNewerRemoval: an install waiting on a purge never writes after a newer removal`() async throws {
        let rig = try await OnDemandRig(.off)
        let other = try await rig.installOther()
        // A crash between a purge's tombstone and its removal left both; the next install of the id completes that purge.
        let repository = try DirectoryProfileRepository(directory: rig.harness.directory)
        let loaded = try repository.load(other.id)
        let record = try #require(loaded)
        try repository.stagePurge(RegisteredProfile(registration: record.registration, ownerUID: record.ownerUID))
        let purge = Latch()
        await rig.harness.registry.setPurgePause { await purge.wait() }
        let install = Task { await rig.controller.installProfileCAS(other, expectedRevision: nil, context: rig.context) }
        try await purge.waited()
        #expect(await rig.send(.removeProfile(other.id, purgeSecrets: false)) == .ok)
        purge.open()
        #expect(await install.value == .profileRevisionConflict(currentRevision: nil))
        #expect(try await rig.harness.registry.ownerUID(for: other.id) == nil, "an older install resurrected a newer removal")
    }

    /// Audit of change 3 (the purge replay's empty scope): a crash left purges of A and B staged with their registrations;
    /// an install of B completes B's purge and is held in its deletion; the startup replay removes A and is held in A's
    /// deletion; the install then commits. The replay reads the tombstones again before B, so it never removes the
    /// reinstalled B.
    @Test
    func `PurgeReplayRereadsTombstones: a reinstall completed during the replay's earlier deletion keeps its registration`() async throws {
        let first = Shared<UUID?>(nil)
        let rig = try await OnDemandRig(.off, repository: { PurgeOrderRepository(base: $0, first: first) })
        let profileA = try await rig.installOther(), profileB = try await rig.installOther()
        first.withLock { $0 = profileA.id }
        let repository = try DirectoryProfileRepository(directory: rig.harness.directory)
        for profile in [profileA, profileB] {
            let loaded = try repository.load(profile.id)
            let record = try #require(loaded)
            try repository.stagePurge(RegisteredProfile(registration: record.registration, ownerUID: record.ownerUID))
        }
        let gates = PurgeGates()
        await rig.harness.registry.setPurgePause(gates.pause)
        let install = Task { await rig.controller.installProfileCAS(profileB, expectedRevision: nil, context: rig.context) }
        try await gates.first.waited()
        let startup = Task { try await rig.controller.reconcileAtStartup() }
        try await gates.second.waited()
        gates.first.open()
        #expect(await install.value == .profileRevision(1))
        gates.second.open()
        _ = try? await startup.value
        #expect(try await rig.harness.registry.ownerUID(for: profileA.id) == nil)
        #expect(try await rig.harness.registry.ownerUID(for: profileB.id) == OnDemandRig.uid, "the replay removed the reinstalled B")
    }

    /// Survivor F6: the purge deletions are gated separately; a second deletion of the same tombstone, if a reinstall starts
    /// one, finishes first; the reinstall still waits for the first deletion, which never deletes what it publishes.
    @Test
    func `ReinstallWaitsForFirstPurge: a reinstall waits for the first deletion even when a second one finishes first`() async throws {
        let rig = try await OnDemandRig(.off)
        let other = try await rig.installOther()
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        let gates = PurgeGates()
        await rig.harness.registry.setPurgePause(gates.pause)
        let removal = Task { await rig.send(.removeProfile(other.id, purgeSecrets: true)) }
        try await gates.first.waited()
        let reinstalled = Shared(false)
        let reinstall = Task {
            try await rig.harness.registry.installProfile(other, expectedRevision: nil, connectionUID: OnDemandRig.uid)
            try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
            reinstalled.withLock { $0 = true }
        }
        try await waitForCondition { await rig.harness.registry.installsAwaitingPurge(of: other.id) == 1 }
        gates.second.open()
        try? await Task.sleep(for: .milliseconds(300)) // Room for a reinstall that does not wait for the first deletion.
        #expect(!reinstalled.withLock { $0 }, "the reinstall finished while the first purge was still deleting")
        gates.first.open()
        try await reinstall.value
        #expect(await removal.value == .ok)
        #expect(await rig.secretsStored(other.id), "the first purge deleted the reinstalled profile's secrets")
    }

    /// Survivor F1: with the on-demand tunnel up, a manual connect is held at its secure-install check and a newer disarm is
    /// received; the disarm supersedes the connect and drops its manual hold, so it stops the tunnel before the connect is
    /// released.
    @Test
    func `DisarmSupersedesHeldManualConnect: the disarm stops the tunnel while an older manual connect is held`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        await secure.holdNext()
        let connect = Task { try await rig.connect() }
        try await secure.latch.waited()
        let disarmed = Shared(false)
        let disarm = Task {
            let reply = await rig.send(.disarmOnDemand(profileID: rig.profile.id))
            disarmed.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { disarmed.withLock { $0 } }) != nil
        let intentAfterDisarm = rig.intent
        secure.latch.open()
        #expect(completed, "the disarm waited behind the held manual connect")
        #expect(await disarm.value == .ok)
        #expect(intentAfterDisarm == nil, "the disarm left the tunnel up while an older manual connect held the profile")
        if case .started = try await connect.value {
            Issue.record("a manual connect received before the disarm started after it")
        }
        await rig.idle()
        #expect(rig.intent == nil)
        #expect(try await rig.consistent(nil))
    }

    /// Survivors F2 and F8: a manual start fails in its engine and keeps its intent; a manual stop is held after its owner
    /// lookup; the due retry is derived from the failed start's admission, so the stop's fence makes it born dead: no
    /// restart, and the stop then succeeds.
    @Test
    func `DueRetryNeverOutrunsHeldStop: a failed start's retry is born dead behind a newer manual stop, which succeeds`() async throws {
        let rig = try await OnDemandRig(.off)
        rig.harness.trace.fail(at: "engine.up")
        guard case .error = try await rig.connect() else { Issue.record("the failed start reported success"); return }
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
        #expect(await rig.controller.recoveryObservation().retryAt != nil)
        let engines = rig.harness.trace.calls.filter { $0 == "engine.create" }.count
        let gate = PointGate { $0 == .stopping(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let stop = Task { await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested)) }
        try await gate.reached()
        rig.harness.clock.advance(.seconds(5))
        try? await rig.controller.tick()
        #expect(rig.harness.trace.calls.filter { $0 == "engine.create" }.count == engines, "the retry restarted after a newer stop")
        gate.open()
        #expect(await stop.value == .ok, "the newer stop lost to the failed start's retry")
        #expect(rig.intent == nil)
        #expect(await rig.controller.status.phase == .idle)
    }

    /// Survivor F4a (latest-wins supersession): an arm is held at its secure-install check; a newer arm of another profile is
    /// admitted and then fails; the older arm stays superseded and never commits.
    @Test
    func `OlderArmStaysSuperseded: a held arm never commits after a newer arm that then failed`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), secureInstall: secure)
        let unarmable = try await rig.installOther(.off)
        await secure.holdNext()
        let arm = Task { try await rig.arm() }
        try await secure.latch.waited()
        #expect(try await rig.arm(unarmable.id) == .error(.onDemandNotConfigured))
        secure.latch.open()
        #expect(try await arm.value != .ok, "an arm superseded by a newer arm committed after that arm failed")
        await rig.idle()
        #expect(try await rig.consistent(nil))
        #expect(rig.intent == nil)
    }

    /// Fires the 60 s watchdog of the operation in the serial slot.
    private static func expireOperation(_ rig: OnDemandRig) async throws {
        try await waitForCondition { rig.harness.clock.pendingSleeps.contains(.seconds(60)) }
        rig.harness.clock.advance(.seconds(60))
    }
}
