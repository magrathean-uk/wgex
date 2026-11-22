// SPDX-License-Identifier: MIT
import WGEXCore

/// One atomic controller read, including the UID that may receive its status.
public struct StatusMeasurement: Sendable {
    /// Status, active profile and operation state sampled together with both clocks.
    public let status: TunnelStatus
    /// Protection owner captured in the same actor turn; nil denotes an unowned status.
    public let ownerUID: UInt32?
    /// The journal's protection policy captured in the same actor turn; nil when the service has no journal.
    public let journalPolicy: JournalPolicyName?
    #if WGEX_LAB_BUILD
        /// The journal-owned pf reference, captured in the same actor turn.
        public let ownerPFToken: String?
    #endif
    /// The uninstall marker the journal holds, captured in the same actor turn (M05-T07); nil when none was requested.
    public var uninstall: UninstallProgress?

    #if WGEX_LAB_BUILD
        /// Binds measurement and delivery scope before either crosses an asynchronous boundary.
        public init(status: TunnelStatus, ownerUID: UInt32?, journalPolicy: JournalPolicyName? = nil, ownerPFToken: String? = nil) {
            self.status = status
            self.ownerUID = ownerUID
            self.journalPolicy = journalPolicy
            self.ownerPFToken = ownerPFToken
        }
    #else
        /// Binds measurement and delivery scope before either crosses an asynchronous boundary.
        public init(status: TunnelStatus, ownerUID: UInt32?, journalPolicy: JournalPolicyName? = nil) {
            self.status = status
            self.ownerUID = ownerUID
            self.journalPolicy = journalPolicy
        }
    #endif
}

package extension StatusMeasurement {
    /// The same measurement with its status replaced, keeping the owner and the journal reads of its controller turn.
    func replacing(status: TunnelStatus) -> StatusMeasurement {
        #if WGEX_LAB_BUILD
            var result = StatusMeasurement(status: status, ownerUID: ownerUID, journalPolicy: journalPolicy, ownerPFToken: ownerPFToken)
        #else
            var result = StatusMeasurement(status: status, ownerUID: ownerUID, journalPolicy: journalPolicy)
        #endif
        result.uninstall = uninstall
        return result
    }
}
