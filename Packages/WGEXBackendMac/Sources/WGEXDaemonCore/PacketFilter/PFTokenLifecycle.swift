// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

/// Serial ownership operations, invoked only after the enforcer has replaced any tunnel passes with blocking rules.
package actor PFTokenLifecycle {
    private let runner: PFCtl
    private let journal: any PFTokenJournalling
    private var bootSession: UUID?
    private let onExternalRelease: @Sendable () -> Void
    private var state: PFTokenState
    private var checked = false
    private var reportedExternalRelease = false

    package init(
        runner: PFCtl,
        journal: any PFTokenJournalling,
        bootSession: UUID?,
        onExternalRelease: @escaping @Sendable () -> Void,
    ) throws {
        self.runner = runner; self.journal = journal; self.bootSession = bootSession; self.onExternalRelease = onExternalRelease
        state = try journal.readState()
    }

    package func reconcile(force: Bool = false) async throws -> String? {
        guard !checked || force else { return state.token }
        let previous = state
        let bootSession = try currentBoot()
        if state.bootSession != bootSession {
            state.token = nil; state.bootSession = nil; state.pid = nil
        }
        let rows = try await PacketFilterReadback.references(runner.references())
        if let token = state.token, !rows.contains(where: { $0.token == token && $0.pid == state.pid && $0.process == "pfctl" }) {
            state.token = nil; state.bootSession = nil; state.pid = nil
            if !reportedExternalRelease {
                reportedExternalRelease = true; onExternalRelease()
            }
        }
        try await compensateAttempt(rows)
        if state != previous {
            try journal.writeState(state)
        }
        #if WGEX_LAB_BUILD
            if !checked, state.token != nil {
                DaemonDiagnostics.token(.recovered)
            }
        #endif
        checked = true
        return state.token
    }

    package func acquire() async throws -> String {
        _ = try await reconcile(force: true)
        if let token = state.token {
            try await ensureEnabled()
            return token
        }
        let attemptBoot = try currentBoot(), journal = journal
        do {
            let token = try await runner.enable { pid in
                guard pid > 0 else { throw DaemonFailure.pfToken }
                try journal.writeState(PFTokenState(attempt: PFEnableAttempt(bootSession: attemptBoot, pid: pid, at: Date())))
            }
            // A failed commit leaves the durable attempt available for PID-based compensation.
            guard let pid = try journal.readState().attempt?.pid else { throw DaemonFailure.pfJournal }
            let next = PFTokenState(token: token, bootSession: attemptBoot, pid: pid)
            try journal.writeState(next)
            state = next
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.token(.acquired)
            #endif
            return token
        } catch {
            state = try journal.readState()
            checked = false
            // Includes malformed successful output, timeout, and a failed token commit.
            // A failed compensation keeps the attempt durable for the next retry/start.
            _ = try await reconcile(force: true)
            throw error
        }
    }

    package func release(_ token: String) async throws {
        // Re-prove ownership immediately before release. A disappeared token is discarded, never -X'd.
        guard try await reconcile(force: true) == token, state.bootSession == bootSession else { return }
        try await releaseReference(token)
        state.token = nil; state.bootSession = nil; state.pid = nil
        try journal.writeState(state)
    }

    private func releaseReference(_ token: String) async throws {
        do { try await runner.release(token: token) }
        catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.token(.referenceLeaked)
                DaemonDiagnostics.verificationFailure(.referenceLeaked)
            #endif
            throw error
        }
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.token(.released)
        #endif
    }

    private func ensureEnabled() async throws {
        if try await runner.isEnabled() {
            return
        }
        try await runner.command(["-e"])
        guard try await runner.isEnabled() else { throw DaemonFailure.pfVerification }
    }

    private func currentBoot() throws -> UUID {
        if let bootSession {
            return bootSession
        }
        let value = try SystemBootSession.read()
        bootSession = value
        return value
    }

    private func compensateAttempt(_ rows: [PacketFilterReadback.Reference]) async throws {
        guard let attempt = state.attempt else { return }
        if try attempt.bootSession == currentBoot() {
            for row in rows where row.pid == attempt.pid && row.process == "pfctl" && row.token != state.token && row.matchesAttempt(
                at: attempt.at,
                now: Date(),
            ) {
                try await releaseReference(row.token)
            }
        }
        state.attempt = nil
    }
}
