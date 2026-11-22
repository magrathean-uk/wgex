// SPDX-License-Identifier: MIT
// Explicit module access keeps mutable bookkeeping out of the package interface.
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Endpoint candidates, peer handshakes and rotation retries; never encoded into the resource journal.
internal struct EndpointRotationState {
    internal var candidates: [PublicKey: [Endpoint]] = [:]
    internal var hosts: [PublicKey: String] = [:]
    internal var indices: [PublicKey: Int] = [:]
    internal var handshakePeers: Set<PublicKey> = []
    internal var attemptStarted: Duration?
    internal var backoffSeconds: Int = 5
    internal var awaitingIPv6 = false
    internal var retryTask: Task<Void, Never>?
}

/// The intended tunnel's exclusions (DEC-087): literal ranges and the addresses its host names last resolved to; never
/// encoded into the resource journal (the routes it shaped are). A restarted daemon passes none until the next start.
package struct ExclusionResolutionState {
    package var profileID: UUID?
    package var literal: [IPAddressRange] = []
    package var resolved: [IPAddressRange] = []
    package var unresolved: [String] = []
    /// The profile's excluded local ports (DEC-126); literal, nothing to resolve.
    package var ports: [PortExclusion] = []

    /// Literal and resolved ranges, canonical and sorted.
    package var ranges: [IPAddressRange] {
        Array(Set(literal + resolved)).sorted()
    }
}

/// Maintenance deadlines and stable-active retry history; never encoded into the resource journal.
internal struct MaintenanceState {
    internal var retryAt: Duration?
    internal var retryAttempt: Int = 0
    internal var stableActiveSince: Duration?
    internal var securePolicyPending: Bool = false
}

/// Startup retry ownership, secure-install observations and recovery controls.
internal struct StartupState {
    internal var tickRetryAt: Duration?
    internal var tickRetryAttempt: Int = 0
    internal var failurePublishedFor: UUID?
    internal var controlID: UUID = .init()
    /// The control identity the operation watchdog rotated away: its stage ended by expiry, not by a user control.
    internal var expiredControlID: UUID?
    /// The reserved boot-intent start, from its reservation until its own stage ends. While it is set the serial slot is
    /// never empty: reconciliation creates the start's task and assigns the slot before it returns.
    internal var bootStart: PendingBootStart?
    /// The boot start's stage as stage 1 handed it over, kept until the next startup begins: stage 2's own cleanup clears
    /// `bootStart`, so a stage 2 that ends before the stage-1 waiter resumes must still be found, and observed, from here
    /// (M1-30 NF1). `slot` is also the serial slot stage 1 itself held before the hand-over moved it to the start's task:
    /// a stage-1 deadline that reaches the controller afterwards finds that slot and ends no stage (M1-29 R1).
    internal var handedOver: HandedOverStage?
    internal var retry: (@Sendable () async -> Void)?
    /// Re-enters the runtime's startup sequence after the uninstall fence lifts (M05-T18); nil without a runtime.
    internal var resume: (@Sendable () async -> Void)?
    internal var bootSelectionSuppressed: Bool = false
    internal var reconciliationPending: Bool = false
    internal var installWasVerified: Bool = false
    internal var secureInstallRegressed: Bool = false
}

internal struct HandedOverStage {
    internal let controlID: UUID
    internal let stage: PendingBootStart.Stage
    /// The slot stage 1 held, which the hand-over replaced.
    internal let stage1Slot: UUID
}

/// Reconciliation's output for the boot intent: the registration to start and the generation already reserved for it,
/// with the control identity of the stage that reserved it (a stale stage's reservation is never handed over).
internal struct PendingBootStart {
    internal let registration: DaemonProfile
    internal let generation: Generation
    internal let controlID: UUID
    /// The start's own task and the slot identity it was assigned, set by the hand-over inside reconciliation.
    internal var stage: Stage?

    internal struct Stage {
        internal let task: Task<Void, any Error>
        internal let slot: UUID
    }
}

/// Launch identity retained by a live cutover across recovery.
internal struct CutoverBookkeeping {
    internal let launchID: UUID = .init()
}

/// A bounded startup stage ran out of its own budget. The controller has already published the measured state and
/// rotated its control identity; unlike a fence cancellation, the runtime answers this with backoff and no instant requeue.
package struct StartupOperationExpired: Error, Sendable {}
