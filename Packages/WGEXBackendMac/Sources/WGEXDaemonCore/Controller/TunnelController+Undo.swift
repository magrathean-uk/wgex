// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

package extension TunnelController {
    /// Rollback runs in the predecessor's owned task, even when that task is cancelled.
    /// No cancellation-sensitive checkpoint is used during cleanup; resource records are retired only after success.
    /// Every step that ran is undone even when another fails; a step that never ran has nothing to remove. The first
    /// failure is rethrown with its own fixed diagnostic vocabulary (M1-19 D15).
    func undo(_ generation: Generation) async throws {
        guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
        try withdrawCaptiveException()
        let document = journal.snapshot()
        let resource = resource(generation)
        let attempted = resource.attemptedSteps
            .union(document.entries.filter { $0.generation == generation && $0.action == .willApply }.map(\.step))
        try await acquireUndoToken()
        let blocking: PacketFilterPolicy = intended != nil ? .error : (settings.lockdown ? .lockdown : .disconnecting)
        let previousReason = snapshot.recoveryFailureReason
        // Withdraw a possible tun pass before dismantling any resource.
        let unmeasured = try await withdrawTunnelPass(blocking, generation: generation)
        var failures: [UndoFailure] = []
        if attempted.contains(.installDNS), resource.dns != nil {
            failures += await undoResource(.installDNS, generation: generation) { try await ports.dns.remove(generation: generation) }
        }
        if attempted.contains(.installRoutes) {
            failures += await undoResource(.installRoutes, generation: generation) { try await ports.routes.removeRoutes(of: generation) }
        }
        if attempted.contains(.configureInterface), let identity = resource.identity {
            failures += await undoResource(.configureInterface, generation: generation) {
                try await offActor(.removeAddresses) {
                    try await OffActor.removeAddresses(ports.device, identity: identity, generation: generation)
                }
                // The actor was released during the ioctls. Rollback never stops for a newer generation or a cancellation, but
                // a generation the watchdog abandoned in the meantime is the next reconciliation's: go no further.
                guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
            }
        }
        // Every await above released the actor: a generation the watchdog abandoned meanwhile belongs to the next
        // reconciliation, which shuts every engine down and removes the journalled resources itself.
        guard !abandonedGenerations.contains(generation) else { throw DaemonFailure.journalStaleGeneration }
        failures += try await undoEngine(generation, attempted: attempted)
        if let first = failures.first {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.stepFailed(.undo, step: first.step)
            #endif
            throw Self.typedUndoFailure(first.error)
        }
        if unmeasured, intended != nil || settings.lockdown {
            try await measureUndoPolicy(blocking, generation: generation, previousReason: previousReason)
        }
        try journal.mutate(generation: nil) { $0.resources.removeAll { $0.generation == generation } }
        if intended == nil, !settings.lockdown {
            try await applyPolicy(.disconnected, generation: generation, recovery: true)
            if unmeasured {
                snapshot.recoveryFailureReason = previousReason == .blockingPolicyFailed ? nil : previousReason
            }
        }
    }

    /// A failure whose catalogue row withholds its vocabulary is named by the boundary that failed: an unmeasured or
    /// refused blocking policy is a PacketFilterFailure verification. Port, host and engine failures keep their own.
    static func typedUndoFailure(_ error: any Error) -> any Error {
        guard let failure = error as? DaemonFailure else { return error }
        switch failure.kind {
        case .pfCanaryFailed, .controllerPolicyVerificationFailed: return DaemonFailure.pfVerification
        default: return failure
        }
    }

    /// Loads the blocking policy before any resource is dismantled and reports whether it is still unmeasured. A canary
    /// failure leaves the rules loaded: only their evaluation is unmeasured, because under the tunnel's /1 routes
    /// without the scoped canary route the bound probe has no route (ENETUNREACH, M1-19 D15). Teardown then continues
    /// and the policy is measured once those routes are gone. Any other failure stops the undo with nothing dismantled.
    private func withdrawTunnelPass(_ policy: PacketFilterPolicy, generation: Generation) async throws -> Bool {
        do {
            try await applyPolicy(policy, generation: generation, recovery: true)
            return false
        } catch let failure as DaemonFailure where failure.kind == .pfCanaryFailed {
            return true
        } catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.stepFailed(.undo, step: .blocking)
            #endif
            throw Self.typedUndoFailure(error)
        }
    }

    /// Measures the retained blocking policy after the tunnel's routes are gone; the record is kept if it still fails.
    private func measureUndoPolicy(
        _ policy: PacketFilterPolicy, generation: Generation, previousReason: RecoveryFailureReason?,
    ) async throws {
        do { try await applyPolicy(policy, generation: generation, recovery: true) }
        catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.stepFailed(.undo, step: .blocking)
            #endif
            throw Self.typedUndoFailure(error)
        }
        snapshot.recoveryFailureReason = previousReason == .blockingPolicyFailed ? nil : previousReason
    }

    private func acquireUndoToken() async throws {
        if journal.snapshot().pfToken == nil {
            let token = try await ports.policy.acquireToken(existing: nil)
            try journal.mutate(generation: nil) { $0.pfToken = token }
        }
    }

    /// Returns the engine's down failure; the handle is always shut down and retired.
    private func undoEngine(_ generation: Generation, attempted: Set<DaemonStep>) async throws -> [UndoFailure] {
        var failures: [UndoFailure] = []
        if let engine = engines[generation] {
            if attempted.contains(.engineUp) {
                failures = await undoResource(.engineUp, generation: generation) {
                    do { try await engine.down() } catch EngineError.deviceClosed { /* Closed is already down. */ }
                }
            }
            try await undoStep(.createEngine, generation: generation) { await engine.shutdown() }
            engines.removeValue(forKey: generation)
        }
        return failures
    }

    /// Runs one undo step and returns its failure, if any, so the steps after it still run.
    private func undoResource(_ step: DaemonStep, generation: Generation, action: () async throws -> Void) async -> [UndoFailure] {
        do {
            try await undoStep(step, generation: generation, action: action)
            return []
        } catch {
            return [UndoFailure(step: step, error: error)]
        }
    }

    private func undoStep(_ step: DaemonStep, generation: Generation, action: () async throws -> Void) async throws {
        try entry(step, .undo, generation: generation, recovery: true)
        try await action()
        try entry(step, .didUndo, generation: generation, recovery: true)
    }
}

/// One undo step that failed and its error.
private struct UndoFailure {
    let step: DaemonStep
    let error: any Error
}
