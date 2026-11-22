// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// A repository that can fail the registration read of one profile, or the registration write that enables
/// start-before-login, and forwards everything else (purge replay included).
private final class SweepFaultRepository: ProfileRepository {
    let base: any ProfileRepository
    let unreadable = Shared<UUID?>(nil)
    let failBootWrite = Shared(false)

    init(base: any ProfileRepository) {
        self.base = base
    }

    func load(_ id: UUID) throws -> RegisteredProfile? {
        if id == unreadable.withLock({ $0 }) {
            throw HostTestError.injected
        }
        return try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        if profile.startBeforeLoginOverride == true, failBootWrite.withLock({ $0 }) {
            throw HostTestError.injected
        }
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

    func otherRecords(excluding id: UUID) throws -> [RegisteredProfile] {
        try base.otherRecords(excluding: id)
    }

    func stagePurge(_ record: RegisteredProfile) throws {
        try base.stagePurge(record)
    }

    func finishPurge(_ id: UUID) throws {
        try base.finishPurge(id)
    }

    func pendingPurges() throws -> [RegisteredProfile] {
        try base.pendingPurges()
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        try base.loadOnDemandRecord()
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        try base.saveOnDemandRecord(record)
    }
}

/// The steps of enabling start-before-login at which the daemon can die (`commitBootIntent`): the bundle is published,
/// the older journalled deletion is superseded, then the flag is written durably.
internal enum BootCommitCrash: CaseIterable, Sendable {
    /// Published; the older deletion is still journalled.
    case afterPublication
    /// Published and superseded; the flag write has not started.
    case afterSupersede
    /// The live command is held at its last pause before the flag write, and the daemon is replaced.
    case heldBeforeFlagWrite
    /// The flag write itself fails, and the daemon is replaced.
    case flagWriteFailed
    /// The flag is written: the bundle is claimed.
    case afterFlagWrite
}

private extension OnDemandRig {
    /// A crash and restart on the same state directory, with the replacement's operation log collected.
    func restart(
        logging sink: OperationLogSink,
        repository: (@Sendable (any ProfileRepository) -> any ProfileRepository)? = nil,
    ) async throws -> TunnelController {
        await controller.cancelBackgroundWork()
        let replacement = try harness.replacementController(operationLog: sink.append, repositoryTransform: repository)
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        return replacement
    }

    func enableBootIntent() async throws -> Reply {
        try await controller.handle(
            .setStartBeforeLoginIntent(profileID: profile.id, enabled: true), context: context, secrets: ControllerHarness.bundle(),
        )
    }

    func bootFlag() throws -> Bool {
        try DirectoryProfileRepository(directory: harness.directory).load(profile.id)?.startBeforeLoginOverride == true
    }

    func journalledDeletions() throws -> Set<UUID> {
        try DaemonJournal(directory: harness.directory).snapshot().pendingSecretDeletions
    }

    /// Leaves the state directory as the daemon would at `crash`; a held live command is returned to release afterwards.
    func reproduce(
        _ crash: BootCommitCrash, faults: SweepFaultRepository,
    ) async throws -> (gate: PointGate, command: Task<Reply, any Error>)? {
        let id = profile.id
        switch crash {
        case .afterPublication, .afterSupersede, .afterFlagWrite:
            try await harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: id)
            if crash != .afterPublication {
                try harness.journal.mutate(generation: nil) { $0.pendingSecretDeletions.remove(id) }
            }
            if crash == .afterFlagWrite {
                try await harness.registry.setStartBeforeLogin(id, enabled: true, connectionUID: OnDemandRig.uid)
            }
        case .heldBeforeFlagWrite:
            let gate = PointGate { $0 == .bootCommit(id) }
            await controller.setOnDemandPause(gate.pause)
            let command = Task { try await self.enableBootIntent() }
            try await gate.reached()
            return (gate, command)
        case .flagWriteFailed:
            faults.failBootWrite.withLock { $0 = true }
            #expect(try await enableBootIntent() != .ok)
        }
        return nil
    }
}

private extension OperationLogSink {
    var sweepLines: [String] {
        lines.filter { $0.hasPrefix("bundle sweep:") }
    }
}

/// M05-T02: the startup sweep of unclaimed bundles (M02-T02 risk 2).
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandBundleSweepTests {
    @Test(arguments: BootCommitCrash.allCases)
    func `BootCommitCrashWindow: a crash before the flag write leaves no bundle, after it the bundle stays`(
        crash: BootCommitCrash,
    ) async throws {
        let holder = Shared<SweepFaultRepository?>(nil)
        let rig = try await OnDemandRig(.off, repository: { base in
            let faults = SweepFaultRepository(base: base)
            holder.withLock { $0 = faults }
            return faults
        })
        let faults = try #require(holder.withLock { $0 })
        let id = rig.profile.id
        // An older explicit stop journalled the deletion that enabling start-before-login supersedes.
        try rig.pendDeletion(id)
        let held = try await rig.reproduce(crash, faults: faults)
        if crash != .afterPublication {
            #expect(try rig.journalledDeletions().isEmpty, "the step under test is after the supersession")
        }
        #expect(await rig.secretsStored(), "the step under test is after the publication")
        #expect(try rig.bootFlag() == (crash == .afterFlagWrite))

        let sink = OperationLogSink()
        let replacement = try await rig.restart(logging: sink)
        let claimed = crash == .afterFlagWrite
        #expect(await rig.secretsStored() == claimed)
        #expect(try rig.journalledDeletions().isEmpty)
        switch crash {
        case .afterFlagWrite:
            #expect(sink.sweepLines.isEmpty)
            #expect(await replacement.status.phase == .active(replacement.currentGeneration))
        case .afterPublication:
            // The journalled deletion still names the bundle: its replay removes it, so the sweep finds nothing.
            #expect(sink.sweepLines.isEmpty)
        case .afterSupersede, .heldBeforeFlagWrite, .flagWriteFailed:
            #expect(sink.sweepLines == ["bundle sweep: removed unclaimed bundle \(id.uuidString)"])
            #expect(await replacement.status.phase == .idle)
        }
        if let held {
            // The replaced daemon never resumes in production; release it only after every check.
            held.gate.open()
            _ = try? await held.command.value
        }
    }

    @Test
    func `an armed profile's bundle is claimed and kept`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.anySSID)))
        #expect(try await rig.arm() == .ok)
        await rig.idle()
        #expect(rig.intent == nil, "armed without an intent, so the armed record is the only claim")
        #expect(await rig.secretsStored())
        let sink = OperationLogSink()
        let replacement = try await rig.restart(logging: sink)
        #expect(await replacement.onDemandArmedProfileID == rig.profile.id)
        #expect(await rig.secretsStored())
        #expect(sink.sweepLines.isEmpty)
    }

    @Test
    func `a journalled intent's bundle is claimed and kept`() async throws {
        let rig = try await OnDemandRig(.off)
        guard case .started = try await rig.connect() else { Issue.record("the manual connect failed"); return }
        #expect(rig.intent?.profileID == rig.profile.id)
        // The manual start supplied secrets; store them as a daemon-held bundle under the same intent.
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: rig.profile.id)
        let sink = OperationLogSink()
        let replacement = try await rig.restart(logging: sink)
        #expect(await rig.secretsStored())
        #expect(await replacement.status.phase == .active(replacement.currentGeneration))
        #expect(sink.sweepLines.isEmpty)
    }

    @Test
    func `a bundle whose registration cannot be read is kept and logged`() async throws {
        let rig = try await OnDemandRig(.off)
        let id = rig.profile.id
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: id)
        let sink = OperationLogSink()
        _ = try await rig.restart(logging: sink, repository: { base in
            let faults = SweepFaultRepository(base: base)
            faults.unreadable.withLock { $0 = id }
            return faults
        })
        #expect(await rig.secretsStored())
        #expect(sink.sweepLines == ["bundle sweep: kept bundle \(id.uuidString); claim state unreadable"])
    }

    @Test
    func `only unclaimed bundles go, one line each, and a profile-less bundle is unclaimed`() async throws {
        let rig = try await OnDemandRig(.off)
        let claimed = try await rig.installOther()
        try await rig.harness.registry.setStartBeforeLogin(claimed.id, enabled: true, connectionUID: OnDemandRig.uid)
        let orphan = UUID()
        for id in [rig.profile.id, claimed.id, orphan] {
            try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: id)
        }
        let sink = OperationLogSink()
        _ = try await rig.restart(logging: sink)
        #expect(await !rig.secretsStored(rig.profile.id))
        #expect(await rig.secretsStored(claimed.id))
        #expect(await !rig.secretsStored(orphan))
        #expect(Set(sink.sweepLines) == [
            "bundle sweep: removed unclaimed bundle \(rig.profile.id.uuidString)",
            "bundle sweep: removed unclaimed bundle \(orphan.uuidString)",
        ])
        #expect(sink.sweepLines.count == 2)
        for line in sink.sweepLines {
            #expect(!line.contains("PrivateKey") && line.utf8.count < 100, "a sweep line names the bundle and nothing else")
        }
    }

    @Test
    func `with no leftover bundle the startup logs carry no sweep line`() async throws {
        let rig = try await OnDemandRig(.off)
        #expect(try await rig.harness.store.storedBundleProfileIDs().isEmpty)
        let sink = OperationLogSink()
        let replacement = try await rig.restart(logging: sink)
        #expect(sink.sweepLines.isEmpty)
        #expect(await replacement.status.phase == .idle)
    }

    @Test
    func `the store lists only the bundle names it writes`() async throws {
        let rig = try await OnDemandRig(.off)
        let id = rig.profile.id
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: id)
        let bundles = try rig.harness.directory.directory("secrets").directory("bundles")
        try bundles.replace("not-a-bundle.blob", with: Data([1]))
        try bundles.replace(id.uuidString + "-other.blob", with: Data([1]))
        #expect(try await rig.harness.store.storedBundleProfileIDs() == [id])
    }
}
