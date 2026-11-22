// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-33 N3: the reason a failed startup is published under, pinned both ways. M1-31 added one mapping (a mid-boot
/// secure-install failure keeps its own label); a mapping that is too wide or sits after the resolve-tail check changes
/// every other failure's label, and only a table over several error kinds, with and without the tail, sees that.
@Suite(.timeLimit(.minutes(2)))
private struct StartupFailureClassificationTests {
    private struct Row: Sendable {
        let name: String
        let error: @Sendable () -> any Error
        /// The label with no intent persisted and no resolve step at the journal's tail; the other three combinations follow
        /// from the fallbacks in `classifyStartupFailure`, unless the row's own mapping wins over them.
        let wins: RecoveryFailureReason?
    }

    private static let rows: [Row] = [
        Row(name: "DaemonError.secureInstallRequired", error: { DaemonError.secureInstallRequired }, wins: .secureInstallRequired),
        Row(name: "DaemonError.busy", error: { DaemonError.busy }, wins: nil),
        Row(name: "DaemonError.secretsUnavailable", error: { DaemonError.secretsUnavailable }, wins: nil),
        Row(name: "DaemonError.recovering", error: { DaemonError.recovering }, wins: nil),
        Row(
            name: "DaemonFailure.startup(.monitorStartFailed)",
            error: { DaemonFailure.startup(.monitorStartFailed) },
            wins: .monitorStartFailed,
        ),
        Row(
            name: "DaemonFailure.startup(.secureInstallRequired)",
            error: { DaemonFailure.startup(.secureInstallRequired) },
            wins: .secureInstallRequired,
        ),
        Row(name: "CancellationError", error: { CancellationError() }, wins: nil),
        Row(name: "a foreign error", error: { HostTestError.injected }, wins: nil),
    ]

    private func expected(_ row: Row, intent: Bool, resolveTail: Bool) -> RecoveryFailureReason {
        if let wins = row.wins {
            return wins
        }
        if resolveTail {
            return .resolverUnavailable
        }
        return intent ? .intentStartFailed : .reconciliationFailed
    }

    /// A controller with or without a persisted intent, and a journal whose newest entry is, or is not, a resolve step.
    private func controller(intent: Bool, resolveTail: Bool) async throws -> (TunnelController, ControllerHarness) {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let generation = await harness.controller.currentGeneration
        if !intent {
            try harness.journal.mutate(generation: generation) { $0.intent = nil }
        }
        if resolveTail {
            try harness.journal.mutate(generation: generation) {
                $0.entries.append(DaemonJournalEntry(generation: generation, step: .resolve, action: .didApply))
            }
        }
        let controller = intent ? harness.controller : try harness.replacementController()
        let tail = try DaemonJournal(directory: harness.directory).snapshot().entries.last?.step
        #expect((tail == .resolve) == resolveTail, "the journal tail is not the one the row asks for (\(String(describing: tail)))")
        #expect(await (controller.intended != nil) == intent, "the controller's intent is not the one the row asks for")
        return (controller, harness)
    }

    @Test(arguments: [false, true], [false, true])
    func `every error kind maps to its own reason, with and without a persisted intent and a resolve tail`(
        intent: Bool, resolveTail: Bool,
    ) async throws {
        let (controller, harness) = try await controller(intent: intent, resolveTail: resolveTail)
        defer { _ = harness }
        for row in Self.rows {
            let reason = await controller.classifyStartupFailure(row.error())
            #expect(
                reason == expected(row, intent: intent, resolveTail: resolveTail),
                "\(row.name), intent \(intent), resolve tail \(resolveTail): classified as \(reason)",
            )
        }
    }
}
