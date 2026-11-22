// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct CutoverStartupJournalTests {
    private func arm(_ harness: ControllerHarness) async throws {
        try await harness.install()
        _ = try await harness.controller.startCutover(
            profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
            confirmWithin: 600, secrets: ControllerHarness.bundle(),
        )
    }

    private func replacement(_ harness: ControllerHarness, journal: any DaemonJournalling) -> TunnelController {
        TunnelController(
            registry: harness.registry, secureInstall: VerifiedSecureInstall(), journal: journal, secrets: harness.store,
            ports: DaemonPorts(
                engineFactory: harness.ports, routes: harness.ports, dns: harness.ports, policy: harness.ports,
                resolver: harness.ports, device: harness.ports, verifier: harness.ports, reality: harness.ports,
            ),
            underlay: ControllerHarness.underlay, clock: harness.clock, operationClock: harness.clock,
        )
    }

    @Test(arguments: [false, true])
    func `startup journal failure leaves cutover reconciliation retryable`(_ prepareFirst: Bool) async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let trial = try #require(harness.journal.snapshot().cutover)
        let reopened = try DaemonJournal(directory: StateDirectory(root: harness.root))
        let journal = CutoverToggleJournal(base: reopened)
        let controller = replacement(harness, journal: journal)
        await #expect(throws: DaemonError.protectionUnknown(reason: "cutoverRollbackIncomplete")) {
            if prepareFirst {
                try await controller.prepareStartupBlocking()
            } else {
                try await controller.reconcileAtStartup()
            }
        }
        #expect(journal.snapshot().cutover?.state == trial.state)
        #expect(journal.snapshot().cutover?.rollbackPending == false)
        #expect(journal.snapshot().intent?.profileID == harness.profile.id)
        #expect(await controller.status.protection != .blocked)
        let offset = harness.trace.calls.count
        journal.failWrites(false)
        if prepareFirst {
            try await controller.reconcileAtStartup()
        } else {
            try await controller.prepareStartupBlocking()
            try await controller.reconcileAtStartup()
        }
        let persisted = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(persisted.cutover?.state == .rolledBack(reason: .daemonRestart))
        #expect(persisted.cutover?.rollbackPending == false)
        #expect(persisted.intent == nil)
        #expect(persisted.pfToken == nil)
        #expect(await controller.status.phase == .idle)
        #expect(await controller.status.protection == .unprotected)
        #expect(!harness.trace.calls.dropFirst(offset).contains("pf.error"))
        #expect(!harness.trace.calls.dropFirst(offset).contains("engine.create"))
        #expect(try await !controller.reconcileCutoverAtStartup())
    }

    @Test
    func `arming records launch ownership and legacy trials remain recoverable`() async throws {
        let harness = try ControllerHarness()
        try await arm(harness)
        let record = try #require(harness.journal.snapshot().cutover)
        var fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(record)) as? [String: Any])
        let launchID = try #require(fields["launchID"] as? String)
        #expect(UUID(uuidString: launchID) != nil)
        #expect(try await !harness.controller.reconcileCutoverAtStartup())
        #expect(await harness.controller.cutoverIsArmed)
        fields.removeValue(forKey: "launchID")
        let legacy = try JSONDecoder().decode(CutoverRecord.self, from: JSONSerialization.data(withJSONObject: fields))
        try harness.journal.mutate(generation: nil) { $0.cutover = legacy }
        #expect(try await harness.controller.reconcileCutoverAtStartup())
        #expect(harness.journal.snapshot().cutover?.state == .rolledBack(reason: .daemonRestart))
        #expect(harness.journal.snapshot().intent == nil)
        #expect(await harness.controller.status.protection == .unprotected)
    }
}

private final class CutoverToggleJournal: DaemonJournalling {
    private let base: DaemonJournal
    private let failing = Mutex(true)
    init(base: DaemonJournal) {
        self.base = base
    }

    func failWrites(_ enabled: Bool) {
        failing.withLock { $0 = enabled }
    }

    func snapshot() -> DaemonJournalDocument {
        base.snapshot()
    }

    func allocate(intent: TunnelIntent?, deletingSecretsOf: UUID?) throws -> Generation {
        guard !failing.withLock({ $0 }) else { throw DaemonFailure.journalExhausted }
        return try base.allocate(intent: intent, deletingSecretsOf: deletingSecretsOf)
    }

    func mutate(generation: Generation?, _ body: (inout DaemonJournalDocument) throws -> Void) throws {
        guard !failing.withLock({ $0 }) else { throw DaemonFailure.journalExhausted }
        try base.mutate(generation: generation, body)
    }
}
