// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M05-T07 review r3: an uninstall that meets a cutover trial, armed or with its rollback pending, releases the kill switch
/// (the empty policy, then the WGEX pf reference) before any profile, secret, bundle or boot-flag storage operation.
@Suite(.timeLimit(.minutes(1)))
private struct UninstallCutoverTests {
    enum Trial: CaseIterable, Sendable { case armed, rollbackPending }

    @Test(arguments: Trial.allCases)
    func `the uninstall releases the kill switch before any storage call`(trial: Trial) async throws {
        let harness = try await Self.harness(with: trial)
        let mark = harness.trace.calls.count
        try await harness.controller.uninstall(purgeState: false)
        let calls = Array(harness.trace.calls.dropFirst(mark))
        let released = try #require(calls.firstIndex(of: "pf.release"))
        #expect(calls.prefix(released).allSatisfy { !Self.isStorage($0) })
        #expect(calls.prefix(released).contains("pf.disconnected"))
        #expect(!calls.contains("secrets.delete")) // The trial bundle goes with every other one, after the release.
        for storage in ["registry.removeAll", "secrets.removeAll", "bundles.removeAll", "key.remove"] {
            #expect(calls.dropFirst(released).contains(storage), "Missing storage step: \(storage)")
        }
        try await Self.expectNothingLeft(harness)
    }

    @Test(arguments: Trial.allCases)
    func `a failing release leaves storage untouched, names its step, and a retry finishes`(trial: Trial) async throws {
        let harness = try await Self.harness(with: trial)
        let bundles = try await harness.store.storedBundleProfileIDs()
        harness.trace.fail(at: "pf.release", repeating: true)
        let mark = harness.trace.calls.count
        await #expect(throws: DaemonFailure.uninstall(.releaseReference)) {
            try await harness.controller.uninstall(purgeState: false)
        }
        let failed = Array(harness.trace.calls.dropFirst(mark))
        #expect(failed.contains("pf.release"))
        #expect(!failed.contains { Self.isStorage($0) })
        #expect(harness.journal.snapshot().uninstall?.pendingStep == .releaseReference)
        #expect(harness.journal.snapshot().pfToken != nil && harness.journal.snapshot().cutover == nil)
        #expect(try await harness.store.storedBundleProfileIDs() == bundles)
        #expect(try await harness.registry.ownerUID(for: harness.profile.id) == ControllerHarness.uid)
        harness.trace.fail(at: nil)
        let retry = harness.trace.calls.count
        try await harness.controller.uninstall(purgeState: false)
        let retried = Array(harness.trace.calls.dropFirst(retry))
        let released = try #require(retried.firstIndex(of: "pf.release"))
        #expect(retried.prefix(released).allSatisfy { !Self.isStorage($0) })
        #expect(!retried.contains("engine.shutdown")) // Finished steps are not rerun.
        try await Self.expectNothingLeft(harness)
    }

    @Test
    func `a trial expiring under the uninstall fence is left to the uninstall's own rollback`() async throws {
        let awake = HostClock()
        let harness = try await Self.harness(with: .armed, watchdogClock: awake)
        let trial = try #require(harness.journal.snapshot().cutover)
        await harness.controller.setUninstallStepHook { step in
            if step == .stopTunnel {
                throw HostTestError.injected
            }
        }
        await #expect(throws: DaemonFailure.uninstall(.stopTunnel)) { try await harness.controller.uninstall(purgeState: false) }
        let mark = harness.trace.calls.count
        awake.advance(.seconds(60))
        try await harness.controller.expireCutover(trial.id)
        #expect(harness.trace.calls.count == mark)
        #expect(await harness.controller.cutoverIsArmed)
        await harness.controller.setUninstallStepHook(nil)
        try await harness.controller.uninstall(purgeState: false)
        let calls = Array(harness.trace.calls.dropFirst(mark))
        let released = try #require(calls.firstIndex(of: "pf.release"))
        #expect(calls.prefix(released).allSatisfy { !Self.isStorage($0) })
        try await Self.expectNothingLeft(harness)
    }
}

private extension UninstallCutoverTests {
    static func isStorage(_ call: String) -> Bool {
        call.hasPrefix("registry.") || ["secrets.delete", "secrets.removeAll", "bundles.removeAll", "key.remove"].contains(call)
    }

    /// A harness whose profile writes are traced beside the ports, with a trial armed or with its rollback pending and the
    /// WGEX pf reference still held.
    static func harness(with trial: Trial, watchdogClock: any DaemonClock? = nil) async throws -> ControllerHarness {
        let repositoryTrace = RepositoryTrace()
        let harness = try ControllerHarness(
            repositoryTransform: { TracingRepository(base: $0, trace: repositoryTrace) }, watchdogClock: watchdogClock,
        )
        repositoryTrace.attach(harness.trace)
        try await harness.install()
        _ = try await harness.controller.startCutover(
            profileID: harness.profile.id, connectionUID: ControllerHarness.uid, confirmWithin: 60, secrets: ControllerHarness.bundle(),
        )
        #expect(await harness.controller.cutoverIsArmed)
        if trial == .rollbackPending {
            // The ordinary rollback cannot release the reference, so it stays pending.
            harness.trace.fail(at: "pf.release", repeating: true)
            await #expect(throws: (any Error).self) { try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid) }
            harness.trace.fail(at: nil)
            #expect(harness.journal.snapshot().cutover?.rollbackPending == true)
        }
        #expect(harness.journal.snapshot().pfToken != nil)
        return harness
    }

    static func expectNothingLeft(_ harness: ControllerHarness) async throws {
        #expect(await harness.ports.policy == .disconnected)
        #expect(await harness.ports.token == nil)
        #expect(await harness.ports.ownedRoutes().isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        #expect(await harness.controller.engines.isEmpty)
        let document = harness.journal.snapshot()
        #expect(document.pfToken == nil && document.pfPolicy == .disconnected && document.intent == nil && document.cutover == nil)
        #expect(document.resources.isEmpty && !document.settings.lockdown)
        #expect(document.uninstall?.completed == true)
        #expect(try await harness.registry.ownerUID(for: harness.profile.id) == nil)
        #expect(try await harness.registry.bootIntent() == nil)
        #expect(try await harness.store.storedBundleProfileIDs().isEmpty)
    }
}

/// Routes the profile repository's writes into the harness trace, which exists only once the harness does.
private final class RepositoryTrace: Sendable {
    private let target = Mutex<HostTrace?>(nil)
    func attach(_ trace: HostTrace) {
        target.withLock { $0 = trace }
    }

    func record(_ point: String) throws {
        try target.withLock { $0 }?.record(point)
    }
}

/// The directory repository with every write traced as `registry.<write>`; reads pass through.
private struct TracingRepository: ProfileRepository {
    let base: any ProfileRepository
    let trace: RepositoryTrace
    func load(_ id: UUID) throws -> RegisteredProfile? {
        try base.load(id)
    }

    func save(_ profile: RegisteredProfile) throws {
        try trace.record("registry.save"); try base.save(profile)
    }

    func remove(_ id: UUID) throws {
        try trace.record("registry.remove"); try base.remove(id)
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
        try trace.record("registry.stagePurge"); try base.stagePurge(record)
    }

    func finishPurge(_ id: UUID) throws {
        try trace.record("registry.finishPurge"); try base.finishPurge(id)
    }

    func pendingPurges() throws -> [RegisteredProfile] {
        try base.pendingPurges()
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        try base.loadOnDemandRecord()
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        try trace.record("registry.saveOnDemand"); try base.saveOnDemandRecord(record)
    }

    func removeAll() throws {
        try trace.record("registry.removeAll"); try base.removeAll()
    }
}
