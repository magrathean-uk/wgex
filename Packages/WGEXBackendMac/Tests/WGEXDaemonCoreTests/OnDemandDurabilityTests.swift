// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// A repository that refuses to write an on-demand record arming one profile, or fails the record write numbered
/// `failWrite` (counted from 1), and forwards everything else.
private final class ArmFaultRepository: ProfileRepository {
    let base: any ProfileRepository
    let refused: Shared<UUID?>
    let failWrite = Shared<Int?>(nil)
    let writes = Shared(0)

    init(base: any ProfileRepository, refused: Shared<UUID?> = Shared(nil)) {
        self.base = base
        self.refused = refused
    }

    func load(_ id: UUID) throws -> RegisteredProfile? {
        try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        try base.save(profile)
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        try base.loadOnDemandRecord()
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        let count = writes.withLock { $0 += 1; return $0 }
        if record.armed != nil, record.armed == refused.withLock({ $0 }) {
            throw HostTestError.injected
        }
        if count == failWrite.withLock({ $0 }) {
            throw HostTestError.injected
        }
        try base.saveOnDemandRecord(record)
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

    func otherRecords(excluding id: UUID) throws -> [RegisteredProfile] {
        try base.otherRecords(excluding: id)
    }
}

private extension OnDemandRig {
    /// Fails the on-demand record write that comes `after` writes from now (1 is the next one).
    func failRecordWrite(after count: Int, of faults: ArmFaultRepository) {
        let base = faults.writes.withLock { $0 }
        faults.failWrite.withLock { $0 = base + count }
    }

    /// Arms `other` while the running profile's release fails, leaving its stop owed in the record.
    func switchWithFailedRelease(to other: UUID) async throws {
        harness.trace.fail(at: "routes.remove", repeating: true)
        #expect(try await arm(other) != .ok)
        harness.trace.fail(at: nil)
        await idle()
        #expect(try record()?.releases == [OnDemandRelease(profileID: profile.id, stopsIntent: true)])
    }
}

/// REV-M02-T02 round 3, changes 1 and 2: the selection is one durable write, and a release owes only the claim it saw.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandSelectionDurabilityTests {
    // MARK: Change 1 (H14) one durable write

    @Test
    func `ArmSwitchWriteFailureAndCrashRecovery: a failed write switches nothing and a crash after it completes the switch`() async throws {
        let refused = Shared<UUID?>(nil)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), repository: { ArmFaultRepository(base: $0, refused: refused) })
        let other = try await rig.installOther(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.profileID == rig.profile.id)
        // The switch's single write fails: nothing switches, in memory or on disk, and nothing is owed.
        refused.withLock { $0 = other.id }
        #expect(try await rig.arm(other.id) != .ok)
        refused.withLock { $0 = nil }
        await rig.idle()
        #expect(try await rig.consistent(rig.profile.id))
        #expect(try rig.record() == OnDemandRecord(armed: rig.profile.id))
        #expect(rig.intent?.profileID == rig.profile.id)
        // The daemon dies right after the write: the record already names the target and the stop it owes.
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: other.id)
        let registration = try await rig.harness.registry.registrationForStart(other.id, connectionUID: OnDemandRig.uid).registration
        let commit = try await rig.controller.testArmCommit(other.id, uid: OnDemandRig.uid, expected: registration)
        #expect(commit.releases == [OnDemandRelease(profileID: rig.profile.id, stopsIntent: true)])
        #expect(try rig.record()?.armed == other.id)
        let replacement = try await rig.restart()
        #expect(await replacement.onDemandArmedProfileID == other.id)
        #expect(try rig.record() == OnDemandRecord(armed: other.id))
        let journal = try DaemonJournal(directory: rig.harness.directory).snapshot()
        #expect(journal.intent?.profileID != rig.profile.id, "the released profile's journalled intent survived the replay")
        #expect(await !rig.secretsStored(rig.profile.id))
        #expect(await rig.secretsStored(other.id))
    }

    @Test
    func `a crash after the release and before the record drops it replays the release once`() async throws {
        let holder = Shared<ArmFaultRepository?>(nil)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), repository: { base in
            let faults = ArmFaultRepository(base: base)
            holder.withLock { $0 = faults }
            return faults
        })
        guard let faults = holder.withLock({ $0 }) else { Issue.record("no repository"); return }
        let other = try await rig.installOther(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        // Write 1 switches the selection, the release stops the running profile, write 2 (dropping the release) is lost.
        rig.failRecordWrite(after: 2, of: faults)
        #expect(try await rig.arm(other.id) != .ok)
        faults.failWrite.withLock { $0 = nil }
        await rig.idle() // The newly armed profile starts before the daemon dies.
        #expect(try rig.record()?.releases == [OnDemandRelease(profileID: rig.profile.id, stopsIntent: true)])
        #expect(rig.intent?.profileID != rig.profile.id)
        let replacement = try await rig.restart()
        #expect(try rig.record() == OnDemandRecord(armed: other.id))
        #expect(await replacement.onDemandArmedProfileID == other.id)
        #expect(await !rig.secretsStored(rig.profile.id))
    }

    @Test
    func `a release that fails still triggers the newly armed profile and stays owed`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.anySSID)), underlay: OnDemandRig.wifi)
        let other = try await rig.installOther(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))))
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.profileID == rig.profile.id)
        rig.harness.trace.fail(at: "routes.remove", repeating: true)
        #expect(try await rig.arm(other.id) != .ok)
        rig.harness.trace.fail(at: nil)
        // The arm trigger still ran: the SSID list asks for a fresh reading.
        try await rig.settling()
        #expect(rig.requested.withLock { $0 } == ["en0"])
        #expect(try await rig.consistent(other.id))
        #expect(try rig.record()?.releases == [OnDemandRelease(profileID: rig.profile.id, stopsIntent: true)])
        #expect(await rig.onDemand?.armedProfileID == other.id)
    }

    // MARK: Change 2 (H9) release ownership

    @Test
    func `FailedReleaseThenManualConnect: a manual connect supersedes the owed stop and survives a restart`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther(.interfaces(.wifiOnly(.anySSID)))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        try await rig.switchWithFailedRelease(to: other.id)
        // The user connects the released profile: a newer claim, so the owed stop goes in the override's durable write.
        guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
        #expect(try rig.record()?.releases.contains { $0.profileID == rig.profile.id && $0.stopsIntent } == false)
        // The manual intent is restored at the next start and the replay stops nothing.
        let replacement = try await rig.restart()
        let journal = try DaemonJournal(directory: rig.harness.directory).snapshot()
        #expect(journal.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid), "the replay stopped it")
        #expect(await replacement.status.phase == .active(replacement.currentGeneration))
        #expect(try rig.record() == OnDemandRecord())
    }

    @Test
    func `a boot reservation supersedes the stop a failed release still owes`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther(.interfaces(.wifiOnly(.anySSID)))
        try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
        try await rig.arm(); await rig.idle()
        try await rig.switchWithFailedRelease(to: other.id)
        // The released profile is the start-before-login profile: the next start reserves it, a claim newer than the release.
        let replacement = try await rig.restart()
        let journal = try DaemonJournal(directory: rig.harness.directory).snapshot()
        #expect(journal.intent?.profileID == rig.profile.id, "the replay stopped the boot start")
        #expect(await replacement.status.phase == .active(replacement.currentGeneration))
        #expect(try rig.record() == OnDemandRecord(armed: other.id))
    }

    @Test
    func `ReleaseReplayReadsAfterAdmission: a replay that read an owed stop before a manual connect claimed never stops it`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther(.interfaces(.wifiOnly(.anySSID)))
        try await rig.arm(); await rig.idle()
        try await rig.switchWithFailedRelease(to: other.id)
        // The manual connect is held before its durable claim; a replay admitted meanwhile reads the owed stop and is held
        // before it acts on it; the connect then claims, and the replay's stop, bound to the claim read before its record
        // read, stops nothing.
        let connectGate = PointGate { $0 == .selectionRead }
        let replayGate = PointGate { $0 == .releasing(rig.profile.id) }
        await rig.controller.setOnDemandPause { point in
            await connectGate.pause(point)
            await replayGate.pause(point)
        }
        let connect = Task { try await rig.connect() }
        try await connectGate.reached()
        await rig.controller.scheduleReleaseReplay()
        try await replayGate.reached()
        connectGate.open()
        guard case .started = try await connect.value else { Issue.record("the manual connect failed"); return }
        replayGate.open()
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid), "the replay stopped it")
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
    }

    @Test
    func `a fresh install under an id the record still names is never armed`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        // A removal that bypassed the controller left the selection naming the id; a reinstall must not revive it.
        try await rig.harness.registry.removeProfile(rig.profile.id, purgeSecrets: false, connectionUID: OnDemandRig.uid)
        #expect(try await rig.harness.registry.armedProfile() == nil)
        try await rig.harness.registry.installProfile(rig.profile, expectedRevision: nil, connectionUID: OnDemandRig.uid)
        #expect(try await rig.harness.registry.armedProfile() == nil)
        #expect(try rig.record() == OnDemandRecord(releases: [OnDemandRelease(profileID: rig.profile.id, stopsIntent: false)]))
    }

    // MARK: Optional suggestion: an unreadable record

    @Test
    func `an unreadable on-demand record is reported through recovery status and a disarm repairs it`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        await rig.controller.cancelBackgroundWork()
        try rig.harness.directory.directory("profiles").replace("on-demand.state", with: Data("{\"armed\":".utf8))
        let replacement = try rig.harness.replacementController()
        await #expect(throws: DaemonFailure.startup(.profileUnavailable)) { try await replacement.reconcileAtStartup() }
        #expect(await replacement.status.recoveryFailureReason == .profileUnavailable)
        #expect(await replacement.onDemandArmedProfileID == nil)
        #expect(await replacement.handle(.disarmOnDemand(profileID: rig.profile.id), context: rig.context, secrets: nil) == .ok)
        #expect(try rig.record() == OnDemandRecord())
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        #expect(await replacement.status.recoveryFailureReason == nil)
    }
}
