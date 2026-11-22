// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Holds the first decided on-demand action before it reaches `start` or `stop`, so a test can interleave a manual
/// request exactly where a suspension in the lifecycle's owner or registration lookup would let one in.
private final class ActionGate: Sendable {
    let decisions = Shared<[OnDemandStatus.Decision]>([])
    private let released: AsyncStream<Void>
    private let release: AsyncStream<Void>.Continuation

    init() {
        (released, release) = AsyncStream.makeStream()
    }

    var pause: @Sendable (OnDemandStatus.Decision) async -> Void {
        { [decisions, released] decision in
            let first = decisions.withLock { $0.append(decision); return $0.count == 1 }
            guard first else { return }
            for await _ in released {
                return
            }
        }
    }

    /// Waits until the first action is held and returns its decision; bounded and cancellable.
    func held() async throws -> OnDemandStatus.Decision? {
        try await waitForCondition { [decisions] in decisions.withLock { !$0.isEmpty } }
        return decisions.withLock { $0.first }
    }

    func open() {
        release.yield(); release.finish()
    }
}

/// A repository whose saves fail on demand; reads always pass through.
private final class SaveFaultRepository: ProfileRepository {
    let base: any ProfileRepository
    let failing: Shared<Bool>

    init(base: any ProfileRepository, failing: Shared<Bool>) {
        self.base = base
        self.failing = failing
    }

    func load(_ id: UUID) throws -> RegisteredProfile? {
        try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        if failing.withLock({ $0 }) {
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

    func pendingPurges() throws -> [RegisteredProfile] {
        try base.pendingPurges()
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        try base.loadOnDemandRecord()
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        if failing.withLock({ $0 }) {
            throw HostTestError.injected
        }
        try base.saveOnDemandRecord(record)
    }
}

/// REV-M02-T02 items 2 to 4: stale on-demand actions, secret retention on disarm and durable manual overrides.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandFenceTests {
    // MARK: Stale actions (item 2)

    @Test
    func `a stale on-demand disconnect never clears a manual connect made while it was suspended`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let gate = ActionGate()
        await rig.controller.setOnDemandActionPause(gate.pause)
        try await rig.controller.networkChanged(
            trigger: .configuration, underlay: UnderlayEvent(snapshot: OnDemandRig.wifi, satisfied: true),
        )
        #expect(try await gate.held() == .disconnect)
        let reply = try await rig.controller.handle(
            .startIntent(profileID: rig.profile.id, transport: nil, hasSecrets: true), context: rig.context,
            secrets: ControllerHarness.bundle(),
        )
        guard case .started = reply else { Issue.record("manual start failed: \(reply)"); return }
        gate.open(); await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
        #expect(try await !rig.armedInRegistry())
        #expect(await rig.secretsStored())
    }

    @Test
    func `a stale on-demand connect never restarts a profile the user disconnected while it was suspended`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        let gate = ActionGate()
        await rig.controller.setOnDemandActionPause(gate.pause)
        try await rig.controller.networkChanged(
            trigger: .configuration, underlay: UnderlayEvent(snapshot: OnDemandRig.ethernet, satisfied: true),
        )
        #expect(try await gate.held() == .connect)
        #expect(await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested)) == .ok)
        gate.open(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.controller.status.phase == .idle)
        #expect(try await !rig.armedInRegistry())
        #expect(await rig.controller.onDemandArmedProfileID == nil)
    }

    @Test
    func `a stale action dropped while the profile stays armed is re-evaluated on fresh state`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = ActionGate()
        await rig.controller.setOnDemandActionPause(gate.pause)
        try await rig.controller.networkChanged(
            trigger: .configuration, underlay: UnderlayEvent(snapshot: OnDemandRig.ethernet, satisfied: true),
        )
        #expect(try await gate.held() == .connect)
        // A policy edit changes the armed revision without a manual override; the profile stays armed.
        var edited = rig.profile; edited.onDemand = .interfaces(.wifiOrEthernet(.anySSID))
        #expect(await rig.controller.installProfileCAS(edited, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        gate.open(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        // A second action reached the pause, so the first never reserved: the guards stop an action once intended.
        #expect(gate.decisions.withLock { $0 } == [.connect, .connect])
    }

    // MARK: Secret retention (item 3)

    @Test
    func `disarming an intended start-before-login profile keeps its secrets for the next boot`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
        #expect(rig.intent == nil)
        #expect(await rig.secretsStored())
        #expect(rig.harness.journal.snapshot().pendingSecretDeletions.isEmpty)
        await rig.controller.cancelBackgroundWork()
        let replacement = try rig.harness.replacementController()
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        let journal = try DaemonJournal(directory: rig.harness.directory).snapshot()
        #expect(journal.intent?.profileID == rig.profile.id)
        #expect(journal.intent?.startedOnDemand != true)
        #expect(await (try? rig.harness.store.loadBundle(profileID: rig.profile.id)) != nil)
    }

    @Test
    func `arming another profile keeps the replaced start-before-login profile's secrets`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther(.interfaces(.wifiOnly(.anySSID)))
        try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.profileID == rig.profile.id)
        try await rig.arm(other.id); await rig.idle()
        #expect(rig.intent?.profileID != rig.profile.id)
        #expect(await rig.secretsStored(rig.profile.id))
    }

    // MARK: Durable overrides (item 4)

    @Test
    func `a manual disconnect whose durable disarm fails keeps the profile armed and fails the request`() async throws {
        let failing = Shared(false)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), repository: { SaveFaultRepository(base: $0, failing: failing) })
        try await rig.arm(); await rig.idle()
        failing.withLock { $0 = true }
        #expect(await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested)) != .ok)
        #expect(try await rig.armedInRegistry())
        #expect(await rig.controller.onDemandArmedProfileID == rig.profile.id)
        #expect(rig.intent?.startedOnDemand == true)
        // Memory and disk agree, so a restart sees the same armed profile.
        failing.withLock { $0 = false }
        await rig.controller.cancelBackgroundWork()
        let replacement = try rig.harness.replacementController()
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        #expect(await replacement.onDemandArmedProfileID == rig.profile.id)
    }

    @Test
    func `a manual connect whose durable disarm fails keeps the profile armed and fails the request`() async throws {
        let failing = Shared(false)
        let rig = try await OnDemandRig(
            .interfaces(.ethernetOnly), underlay: OnDemandRig.wifi, repository: { SaveFaultRepository(base: $0, failing: failing) },
        )
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        failing.withLock { $0 = true }
        let reply = try await rig.controller.handle(
            .startIntent(profileID: rig.profile.id, transport: nil, hasSecrets: true), context: rig.context,
            secrets: ControllerHarness.bundle(),
        )
        if case .started = reply {
            Issue.record("the start must fail while the disarm cannot be persisted")
        }
        #expect(rig.intent == nil)
        #expect(try await rig.armedInRegistry())
        #expect(await rig.controller.onDemandArmedProfileID == rig.profile.id)
        #expect(await rig.onDemand?.armedProfileID == rig.profile.id)
    }
}
