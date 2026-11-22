// SPDX-License-Identifier: MIT
import WGEXCore

/// The case name of the protection policy the daemon journal holds, without the endpoints and resolvers some cases carry.
public enum JournalPolicyName: String, Codable, Sendable, Hashable, CaseIterable {
    case disconnected, connecting, connected, disconnecting, error, lockdown, captiveWindow

    public init(_ policy: PacketFilterPolicy) {
        switch policy {
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .connected: self = .connected
        case .disconnecting: self = .disconnecting
        case .error: self = .error
        case .lockdown: self = .lockdown
        case .captiveWindow: self = .captiveWindow
        }
    }
}

/// One status publication with its telemetry: the status (its `sequence`, `measuredAt` and protection state), the journal
/// policy read in the same controller turn and, in Lab builds only, the journal-owned pf reference.
public struct StatusPublication: Codable, Sendable, Hashable {
    public var status: TunnelStatus
    /// The protection policy the journal holds at the measurement; nil when the service has no journal (a test double).
    public var journalPolicy: JournalPolicyName?
    #if WGEX_LAB_BUILD
        /// The journal-owned pf reference. Compiled only into Lab builds: a Release build neither holds nor sends it.
        public var ownerPFToken: String?
    #endif
    /// The uninstall the daemon holds (M05-T07): in progress with the step still owed, or completed. Absent when none was
    /// requested and from a daemon that does not send it.
    public var uninstall: UninstallProgress?

    #if WGEX_LAB_BUILD
        public init(status: TunnelStatus, journalPolicy: JournalPolicyName? = nil, ownerPFToken: String? = nil) {
            self.status = status
            self.journalPolicy = journalPolicy
            self.ownerPFToken = ownerPFToken
        }
    #else
        public init(status: TunnelStatus, journalPolicy: JournalPolicyName? = nil) {
            self.status = status
            self.journalPolicy = journalPolicy
        }
    #endif

    /// The publication a measurement makes.
    package init(_ measurement: StatusMeasurement) {
        #if WGEX_LAB_BUILD
            self.init(status: measurement.status, journalPolicy: measurement.journalPolicy, ownerPFToken: measurement.ownerPFToken)
        #else
            self.init(status: measurement.status, journalPolicy: measurement.journalPolicy)
        #endif
        uninstall = measurement.uninstall
    }
}

/// The `statusTelemetry` reply with the Lab telemetry fixed in ARCHITECTURE.md (M03-T01, DEC-011, DEC-018). The current
/// sample is a fresh measurement with its own `sequence`, showing the state after any control already served; the status
/// keeps its meaning, and the rest is read in the same controller turn. `startup` is the run's first publication.
public struct StatusTelemetry: Codable, Sendable, Hashable {
    public var status: TunnelStatus
    /// The protection policy the journal holds at the measurement; nil when the service has no journal (a test double).
    public var journalPolicy: JournalPolicyName?
    #if WGEX_LAB_BUILD
        /// The journal-owned pf reference. Compiled only into Lab builds: a Release build neither holds nor sends it.
        public var ownerPFToken: String?
    #endif
    /// The run's first status publication (sequence 1, measured as startup's restore ended), kept unchanged for the run
    /// whether or not anyone received it (DEC-018). Absent before it exists, from a daemon that does not send it, and for a
    /// reader the status owner rule does not admit to it.
    public var startup: StatusPublication?
    /// The uninstall the daemon holds, read in the same controller turn as the current sample (M05-T07): in progress with
    /// the step still owed, or completed. Absent when none was requested and from a daemon that does not send it.
    public var uninstall: UninstallProgress?

    #if WGEX_LAB_BUILD
        public init(
            status: TunnelStatus, journalPolicy: JournalPolicyName? = nil, ownerPFToken: String? = nil,
            startup: StatusPublication? = nil,
        ) {
            self.status = status
            self.journalPolicy = journalPolicy
            self.ownerPFToken = ownerPFToken
            self.startup = startup
        }
    #else
        public init(status: TunnelStatus, journalPolicy: JournalPolicyName? = nil, startup: StatusPublication? = nil) {
            self.status = status
            self.journalPolicy = journalPolicy
            self.startup = startup
        }
    #endif

    /// A reply whose current sample is `current`.
    package init(current: StatusPublication, startup: StatusPublication? = nil) {
        #if WGEX_LAB_BUILD
            self.init(status: current.status, journalPolicy: current.journalPolicy, ownerPFToken: current.ownerPFToken, startup: startup)
        #else
            self.init(status: current.status, journalPolicy: current.journalPolicy, startup: startup)
        #endif
        uninstall = current.uninstall
    }

    /// The current sample alone, in the shape of a publication.
    public var current: StatusPublication {
        #if WGEX_LAB_BUILD
            var publication = StatusPublication(status: status, journalPolicy: journalPolicy, ownerPFToken: ownerPFToken)
        #else
            var publication = StatusPublication(status: status, journalPolicy: journalPolicy)
        #endif
        publication.uninstall = uninstall
        return publication
    }
}
