// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

/// One durable transaction store for the controller and pf enable reference. No second token file.
public struct DaemonPFTokenJournal: PFTokenJournalling {
    private let journal: any DaemonJournalling
    public init(journal: any DaemonJournalling) {
        self.journal = journal
    }

    /// Reads the controller's single transaction record.
    public func readState() -> PFTokenState {
        let value = journal.snapshot()
        return PFTokenState(token: value.pfToken, bootSession: value.pfBootSession, pid: value.pfTokenPID, attempt: value.pfEnableAttempted)
    }

    /// Persists token, boot identity and attempt in one atomic journal replacement.
    public func writeState(_ state: PFTokenState) throws {
        guard state.token.map(PacketFilterReadback.validToken) != false else { throw DaemonFailure.pfToken }
        try journal.mutate(generation: nil) {
            $0.pfToken = state.token; $0.pfBootSession = state.bootSession; $0.pfTokenPID = state.pid; $0.pfEnableAttempted = state.attempt
        }
    }

    public func readToken() -> String? {
        journal.snapshot().pfToken
    }

    public func writeToken(_ token: String?) throws {
        guard token.map(PacketFilterReadback.validToken) != false else { throw DaemonFailure.pfToken }
        var state = readState()
        if state.token != token {
            state.bootSession = nil; state.pid = nil
        }
        state.token = token
        try writeState(state)
    }
}
