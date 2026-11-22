// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct CutoverTests {
    private func arm(_ harness: ControllerHarness) async throws {
        try await harness.install()
        _ = try await harness.controller.startCutover(
            profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
            confirmWithin: 60, secrets: ControllerHarness.bundle(),
        )
    }

    @Test
    func `sleep and wall clock advance do not consume awake confirmation time`() async throws {
        let awake = HostClock()
        let harness = try ControllerHarness(watchdogClock: awake)
        try await arm(harness)
        let record = try #require(harness.journal.snapshot().cutover)
        harness.clock.advance(.seconds(7200))
        try await harness.controller.expireCutover(record.id)
        #expect(await harness.controller.status.protection == .protected)
        #expect(await harness.controller.cutoverIsArmed)
        awake.advance(.seconds(60))
        try await harness.controller.expireCutover(record.id)
        try await assertRolledBack(harness, reason: .timeout)
    }

    @Test
    func `late confirmation cannot defeat timeout`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        harness.clock.advance(.seconds(60))
        await #expect(throws: DaemonError.self) { try await harness.controller.confirmCutover(connectionUID: ControllerHarness.uid) }
        #expect(await harness.controller.status.cutover != .confirmed)
        let record = try #require(harness.journal.snapshot().cutover)
        try await harness.controller.expireCutover(record.id)
        try await assertRolledBack(harness, reason: .timeout)
    }

    @Test
    func `persistent policy failure is unknown and an abort retry recovers without blocking`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        harness.trace.fail(at: "pf.disconnected", repeating: true)
        await #expect(throws: DaemonError.self) { try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid) }
        #expect(await harness.controller.status.protection == .unknown)
        #expect(harness.journal.snapshot().cutover?.rollbackPending == true)
        #expect(harness.trace.calls.contains("secrets.delete"))
        harness.trace.fail(at: nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        try await assertRolledBack(harness, reason: .aborted)
    }

    @Test(arguments: [
        DaemonStep.cutoverIntent,
        .cutoverBootIntent,
        .removeDNS,
        .removeRoutes,
        .inspectReality,
        .configureInterface,
        .engineDown,
        .engineShutdown,
        .finalPolicy,
        .releaseToken,
        .deleteSecrets,
        .cutoverComplete,
    ])
    func `checkpoint faults never skip rollback effects`(_ step: DaemonStep) async throws {
        let gate = StepGate(point: step, failing: true, enabled: false)
        let harness = try ControllerHarness(gate: gate)
        try await arm(harness)
        await gate.enable()
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        try await assertRolledBack(harness, reason: .aborted)
        #expect(await !harness.controller.status.cutoverRollbackFailures.isEmpty)
    }

    @Test
    func `normal startup preparation rolls back the trial before its blocking stage`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let replacement = try harness.replacementController()
        let offset = harness.trace.calls.count
        try await replacement.prepareStartupBlocking()
        try await replacement.reconcileAtStartup()
        #expect(await replacement.status.cutover == .rolledBack(reason: .daemonRestart))
        #expect(await replacement.status.protection == .unprotected)
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
    }

    @Test(arguments: [false, true])
    func `startup cutover reconciliation is idempotent after rollback or confirmation`(_ confirmed: Bool) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        if confirmed {
            try await harness.controller.confirmCutover(connectionUID: ControllerHarness.uid)
        }
        let controller = try harness.replacementController()
        if confirmed {
            #expect(try await !controller.reconcileCutoverAtStartup())
        } else {
            #expect(try await controller.reconcileCutoverAtStartup())
        }
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        let status = await controller.status
        let calls = harness.trace.calls
        #expect(try await !controller.reconcileCutoverAtStartup())
        #expect(try await !controller.reconcileCutoverAtStartup())
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == document)
        #expect(await controller.status == status)
        #expect(harness.trace.calls == calls)
        if confirmed {
            try await controller.abortCutover(connectionUID: ControllerHarness.uid)
        }
    }

    @Test
    func `direct lockdown mutation is refused while armed`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        var settings = MacGlobalSettings.defaults
        settings.lockdown = true
        let requested = settings
        await #expect(throws: DaemonFailure(code: .slotRefused)) { try await harness.controller.setGlobalSettings(requested) }
        #expect(!harness.journal.snapshot().settings.lockdown)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
    }

    @Test
    func `arm uses normal start and awake time expiry removes every owned resource`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let deadline = harness.clock.wallNow.addingTimeInterval(60)
        #expect(await harness.controller.status.cutover == .armed(deadline: deadline))
        #expect(await harness.controller.status.protection == .protected)
        let record = try #require(harness.journal.snapshot().cutover)
        harness.clock.advance(.seconds(60))
        try await harness.controller.expireCutover(record.id)
        try await assertRolledBack(harness, reason: .timeout)
    }

    @Test
    func `confirm persists and an obsolete timer cannot roll back confirmed intent`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let record = try #require(harness.journal.snapshot().cutover)
        try await harness.controller.confirmCutover(connectionUID: ControllerHarness.uid)
        harness.clock.advance(.seconds(3601))
        try await harness.controller.expireCutover(record.id)
        #expect(await harness.controller.status.cutover == .confirmed)
        #expect(harness.journal.snapshot().cutover?.state == .confirmed)
        #expect(harness.journal.snapshot().intent?.profileID == harness.profile.id)
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(await replacement.status.cutover == .confirmed)
        #expect(await replacement.status.protection == .protected)
    }

    @Test
    func `abort is immediate and idempotent`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        try await assertRolledBack(harness, reason: .aborted)
    }

    @Test
    func `reboot while armed rolls back before any blocking or intent restore`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let offset = harness.trace.calls.count
        let replacement = try harness.replacementController()
        try await replacement.reconcileAtStartup()
        #expect(await replacement.status.cutover == .rolledBack(reason: .daemonRestart))
        #expect(await replacement.status.protection == .unprotected)
        let persisted = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(persisted.intent == nil)
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
        #expect(!harness.trace.calls.dropFirst(offset).contains("engine.create"))
        #expect(await harness.ports.ownedRoutes().isEmpty)
        #expect(persisted.pfToken == nil)
    }

    @Test(arguments: [true, false])
    func `armed cutover refuses lockdown and boot intent`(_ lockdown: Bool) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        var settings = MacGlobalSettings.defaults
        settings.lockdown = true
        let request: Request = lockdown ? .setGlobalSettings(settings)
            : .setStartBeforeLoginIntent(profileID: harness.profile.id, enabled: true)
        let reply = await harness.controller.handle(request, context: context(harness), secrets: nil)
        #expect(reply == .error(.busy))
        #expect(!harness.journal.snapshot().settings.lockdown)
        #expect(try await harness.registry.bootIntent() == nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
    }

    @Test(arguments: [
        "dns.remove",
        "routes.remove",
        "device.remove",
        "engine.down",
        "pf.disconnected",
        "pf.release",
        "secrets.delete",
    ])
    func `rollback attempts every step after each adapter fault and never finishes blocked`(_ fault: String) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let offset = harness.trace.calls.count
        harness.trace.fail(at: fault)
        try? await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        let calls = Array(harness.trace.calls.dropFirst(offset))
        for point in [
            "dns.remove",
            "routes.remove",
            "device.remove",
            "engine.down",
            "engine.shutdown",
            "pf.disconnected",
            "pf.release",
            "secrets.delete",
        ] {
            #expect(calls.contains(point), "Missing rollback step: \(point)")
        }
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(await harness.ports.policy == .disconnected)
        #expect(await harness.ports.token == nil)
        #expect(harness.journal.snapshot().intent == nil)
        #expect(await harness.controller.status.cutover == .rolledBack(reason: .aborted))
        #expect(await harness.controller.status.recoveryFailureReason == nil)
        let record = try #require(harness.journal.snapshot().cutover)
        #expect(!record.failures.isEmpty)
    }

    @Test(arguments: [59, 3601, Int.max])
    func `invalid windows have no effects`(_ seconds: Int) async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        await #expect(throws: DaemonError.self) {
            try await harness.controller.startCutover(
                profileID: harness.profile.id, connectionUID: ControllerHarness.uid, confirmWithin: seconds,
                secrets: ControllerHarness.bundle(),
            )
        }
        #expect(harness.journal.snapshot().cutover == nil)
        #expect(harness.trace.calls.isEmpty)
    }

    private func assertRolledBack(_ harness: ControllerHarness, reason: CutoverRollbackReason) async throws {
        #expect(await harness.controller.status.cutover == .rolledBack(reason: reason))
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(harness.journal.snapshot().intent == nil)
        #expect(harness.journal.snapshot().pfToken == nil)
        #expect(harness.journal.snapshot().pfPolicy == .disconnected)
        #expect(try await harness.registry.bootIntent() == nil)
        #expect(await harness.ports.ownedRoutes().isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        #expect(await harness.controller.engines.isEmpty)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }

    private func context(_ harness: ControllerHarness) -> DaemonRequestContext {
        DaemonRequestContext(
            peer: VerifiedPeerIdentity(uid: ControllerHarness.uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id], clientBuild: 1,
        )
    }
}

private extension CutoverTests {
    @Test(arguments: [false, true])
    func `trial profile removal is busy until rollback completes`(_ pending: Bool) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        if pending {
            harness.trace.fail(at: "routes.remove", repeating: true)
            await #expect(throws: DaemonError.self) { try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid) }
        }
        let offset = harness.trace.calls.count
        let reply = await harness.controller.handle(
            .removeProfile(harness.profile.id, purgeSecrets: false), context: context(harness), secrets: nil,
        )
        #expect(reply == .error(.busy))
        #expect(try await harness.registry.ownerUID(for: harness.profile.id) == ControllerHarness.uid)
        #expect(harness.trace.calls.count == offset)
        harness.trace.fail(at: nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        try await assertRolledBack(harness, reason: .aborted)
    }

    @Test(arguments: ["abort", "expiry", "restart"])
    func `vanished trial registration cannot strand rollback`(_ trigger: String) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let trial = try #require(harness.journal.snapshot().cutover)
        try await harness.registry.removeProfile(harness.profile.id, purgeSecrets: false, connectionUID: ControllerHarness.uid)
        let controller = try trigger == "restart" ? harness.replacementController() : harness.controller
        if trigger == "restart" {
            #expect(try await controller.reconcileCutoverAtStartup())
        } else if trigger == "expiry" {
            harness.clock.advance(.seconds(60))
            try await controller.expireCutover(trial.id)
        } else {
            try await controller.abortCutover(connectionUID: ControllerHarness.uid)
        }
        let persisted = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(persisted.cutover?.rollbackPending == false)
        #expect(persisted.intent == nil)
        #expect(persisted.pfToken == nil)
        #expect(await controller.status.phase == .idle)
        #expect(await controller.status.protection == .unprotected)
        #expect(await controller.status.recoveryFailureReason == nil)
        #expect(await controller.handle(.setGlobalSettings(.defaults), context: context(harness), secrets: nil) == .ok)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }

    @Test
    func `confirmation after completed timeout keeps the timed out category`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let trial = try #require(harness.journal.snapshot().cutover)
        harness.clock.advance(.seconds(60))
        try await harness.controller.expireCutover(trial.id)
        #expect(await harness.controller.handle(.confirmCutover, context: context(harness), secrets: nil) == .error(.tunnel(.timedOut)))
    }

    @Test(arguments: [false, true])
    func `pending cutover rollback cannot enter ordinary blocking recovery`(_ startup: Bool) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        harness.trace.fail(at: "pf.disconnected", repeating: true)
        let controller = try startup ? harness.replacementController() : harness.controller
        if startup {
            #expect(try await controller.reconcileCutoverAtStartup())
        } else {
            await #expect(throws: DaemonError.self) { try await controller.abortCutover(connectionUID: ControllerHarness.uid) }
        }
        let offset = harness.trace.calls.count
        try await controller.verifyRecoveryProtection()
        #expect(await controller.status.protection == .unknown)
        #expect(await !controller.shouldRetryStartup())
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
        #expect(try DaemonJournal(directory: harness.directory).snapshot().cutover?.rollbackPending == true)
        harness.trace.fail(at: nil)
        try await controller.abortCutover(connectionUID: ControllerHarness.uid)
        #expect(await controller.status.protection == .unprotected)
        #expect(try DaemonJournal(directory: harness.directory).snapshot().cutover?.rollbackPending == false)
    }
}
