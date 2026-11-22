// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct CutoverAdmissionTests {
    private func arm(_ harness: ControllerHarness, seconds: Int = 600) async throws {
        try await harness.install()
        _ = try await harness.controller.startCutover(
            profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
            confirmWithin: seconds, secrets: ControllerHarness.bundle(),
        )
    }

    private func context(_ harness: ControllerHarness) -> DaemonRequestContext {
        DaemonRequestContext(
            peer: VerifiedPeerIdentity(uid: ControllerHarness.uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id], clientBuild: 1,
        )
    }

    private func makePending(_ harness: ControllerHarness) async throws {
        try await arm(harness)
        harness.trace.fail(at: "routes.remove", repeating: true)
        await #expect(throws: DaemonError.self) { try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid) }
        #expect(harness.journal.snapshot().cutover?.rollbackPending == true)
    }

    @Test
    func `abort cannot acknowledge pending rollback after waiting for another operation`() async throws {
        let harness = try ControllerHarness()
        try await makePending(harness)
        let gate = StepGate(point: .cutoverIntent)
        let generation = await harness.controller.currentGeneration
        let operation = Task<Void, any Error> { try await gate.adapterCall(.cutoverIntent, generation: generation) }
        await gate.wait()
        await harness.controller.setCutoverTestOperation(operation)
        let abort = Task { try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid) }
        await Task.yield()
        await gate.release()
        await #expect(throws: DaemonError.protectionUnknown(reason: "cutoverRollbackIncomplete")) { try await abort.value }
        await harness.controller.setCutoverTestOperation(nil)
        harness.trace.fail(at: nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
        #expect(harness.journal.snapshot().cutover?.rollbackPending == false)
    }

    @Test
    func `CAS install is refused while rollback is pending`() async throws {
        let harness = try ControllerHarness()
        try await makePending(harness)
        let before = try await harness.registry.installationRevision(harness.profile.id, connectionUID: ControllerHarness.uid)
        let reply = await harness.controller.installProfileCAS(harness.profile, expectedRevision: before, context: context(harness))
        #expect(reply == .error(.busy))
        #expect(try await harness.registry.installationRevision(harness.profile.id, connectionUID: ControllerHarness.uid) == before)
        harness.trace.fail(at: nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
    }

    @Test(arguments: [false, true])
    func `pending stop retries rollback without a disconnecting policy`(_ current: Bool) async throws {
        let harness = try ControllerHarness()
        try await makePending(harness)
        harness.trace.fail(at: nil)
        let offset = harness.trace.calls.count
        let request: Request = current ? .stopCurrent(reason: .userRequested) : .stop(profileID: harness.profile.id, reason: .userRequested)
        #expect(await harness.controller.handle(request, context: context(harness), secrets: nil) == .ok)
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.disconnecting"))
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
        #expect(harness.journal.snapshot().cutover?.rollbackPending == false)
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test(arguments: [false, true])
    func `serial admission refuses a raced trial without a failure policy`(_ lockdown: Bool) async throws {
        let gate = StepGate(point: .validateSecrets)
        let secure = CutoverSecureGate(gate: gate)
        let harness = try ControllerHarness(secureInstall: secure)
        try await harness.install()
        var settings = MacGlobalSettings.defaults
        settings.lockdown = true
        let request: Request = lockdown ? .setGlobalSettings(settings)
            : .setStartBeforeLoginIntent(profileID: harness.profile.id, enabled: true)
        await secure.suspendNext()
        let mutation = Task { await harness.controller.handle(request, context: context(harness), secrets: nil) }
        await gate.wait()
        _ = try await harness.controller.startCutover(
            profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
            confirmWithin: 600, secrets: ControllerHarness.bundle(),
        )
        let offset = harness.trace.calls.count
        await gate.release()
        #expect(await mutation.value == .error(.busy))
        #expect(await harness.controller.cutoverIsArmed)
        #expect(await harness.controller.status.protection == .protected)
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
        #expect(!harness.journal.snapshot().settings.lockdown)
        #expect(try await harness.registry.bootIntent() == nil)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
    }

    @Test
    func `watchdog recovery in the same process leaves a live trial armed`() async throws {
        let harness = try ControllerHarness()
        try await harness.controller.prepareStartupBlocking()
        try await harness.controller.reconcileAtStartup()
        try await arm(harness)
        let trial = try #require(harness.journal.snapshot().cutover)
        let gate = StepGate(point: .cutoverIntent)
        let generation = await harness.controller.currentGeneration
        let operation = Task<Void, any Error> { try await gate.adapterCall(.cutoverIntent, generation: generation) }
        await gate.wait()
        await harness.controller.setCutoverTestOperation(operation)
        let wait = Task { try await harness.controller.boundedResult(operation) }
        for _ in 0 ..< 4000 where !harness.clock.pendingSleeps.contains(.seconds(60)) {
            await Task.yield()
        }
        try #require(harness.clock.pendingSleeps.contains(.seconds(60)))
        harness.clock.advance(.seconds(60))
        await #expect(throws: DaemonFailure.controllerOperationFailed) { try await wait.value }
        await gate.release()
        try await operation.value
        try await harness.controller.tick()
        #expect(harness.journal.snapshot().cutover?.state == trial.state)
        #expect(await harness.controller.cutoverIsArmed)
        #expect(await harness.controller.status.protection == .protected)
        try await harness.controller.abortCutover(connectionUID: ControllerHarness.uid)
    }
}

private actor CutoverSecureGate: SecureInstallChecking {
    private let gate: StepGate
    private var suspended = false
    init(gate: StepGate) {
        self.gate = gate
    }

    func suspendNext() {
        suspended = true
    }

    func status() async -> SecureInstallReport {
        if suspended {
            suspended = false
            try? await gate.before(.validateSecrets, generation: Generation(rawValue: 0))
        }
        return VerifiedSecureInstall().status()
    }

    func perform() async -> SecureInstallReport {
        await status()
    }
}

private extension TunnelController {
    func setCutoverTestOperation(_ task: Task<Void, any Error>?) {
        operation = task
    }
}
