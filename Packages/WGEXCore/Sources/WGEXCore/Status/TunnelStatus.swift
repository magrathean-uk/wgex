// SPDX-License-Identifier: MIT

import Foundation

/// Stable recovery categories. Raw integer codes cross the wire; no adapter text is published.
public enum RecoveryFailureReason: Int, Codable, Sendable, Hashable {
    /// The primary physical interface has not appeared yet.
    case noPrimaryInterface = 1
    /// A persisted profile is missing, corrupt or invalid.
    case profileUnavailable = 2
    /// More than one profile requests boot startup; none is selected.
    case multipleBootProfiles = 3
    /// Endpoint resolution failed on the underlay.
    case resolverUnavailable = 4
    /// Network notification adapters could not start.
    case monitorStartFailed = 5
    /// Kernel resources could not be reconciled.
    case reconciliationFailed = 6
    /// The intended tunnel could not start.
    case intentStartFailed = 7
    /// The blocking policy could not be verified.
    case blockingPolicyFailed = 8
    /// The installed bundle requires repair.
    case secureInstallRequired = 9
}

/// Stable protection notes describing unavailable endpoint connectivity.
public enum ProtectionNote: Int, Codable, Sendable, Hashable {
    /// Some peers require unavailable underlay IPv6; informational if another peer is reachable, otherwise blocked.
    case ipv6Unavailable = 1
    /// No owned tunnel DNS configuration has been applied.
    case dnsUnverified = 2
    /// Network protection could not be verified.
    case verificationFailed = 3
    /// The evaluation canary could not prove packet-filter enforcement.
    case canaryFailed = 4
}

/// Why a trial was reverted; fixed public categories never include adapter descriptions.
public enum CutoverRollbackReason: String, Codable, Sendable, Hashable {
    /// Awake-time confirmation window elapsed.
    case timeout
    /// Owner requested local recovery.
    case aborted
    /// An unconfirmed trial survived a daemon restart or reboot.
    case daemonRestart
    /// Ordinary tunnel start failed after the trial was armed.
    case startFailed
}

/// Durable trial state; the wall deadline is advisory because system sleep pauses expiry.
public enum CutoverState: Codable, Sendable, Hashable {
    /// Confirmation is required before the awake-time deadline.
    case armed(deadline: Date)
    /// The owner committed the trial.
    case confirmed
    /// Rollback was requested; phase and failure fields report completion truthfully.
    case rolledBack(reason: CutoverRollbackReason)
}

/// Mac on-demand state (ADR-030 section 8). It never carries an SSID.
public struct OnDemandStatus: Codable, Sendable, Hashable {
    /// Network class of the primary interface.
    public enum Network: String, Codable, Sendable, Hashable { case none, ethernet, wifi }

    /// Why the SSID is unknown.
    public enum SSIDUnavailableReason: String, Codable, Sendable, Hashable { case noReporter, notAuthorised, timedOut, unreadable }

    /// What the daemon knows of the SSID; the value itself never leaves the daemon.
    public enum SSIDState: Codable, Sendable, Hashable {
        /// The armed policy has no SSID list, or the network is not Wi-Fi.
        case notRequired
        case known
        /// Waiting for a fresh report from the app.
        case settling
        case unavailable(SSIDUnavailableReason)
    }

    /// Why a decision holds.
    public enum HoldReason: String, Codable, Sendable, Hashable { case noNetwork, ssidUnavailable, anotherTunnelActive }

    /// Why evaluation is paused.
    public enum PauseReason: String, Codable, Sendable, Hashable { case ownerNotConsoleUser, recovering, cutoverArmed }

    /// The last evaluation's outcome.
    public enum Decision: Codable, Sendable, Hashable {
        case connect
        case disconnect
        case hold(HoldReason)
        case paused(PauseReason)
    }

    /// The armed profile; nil when none is armed.
    public var armedProfileID: UUID?
    /// The current intent was started by on-demand.
    public var activated: Bool
    public var network: Network
    public var ssid: SSIDState
    /// Nil before the first evaluation since arming or daemon start.
    public var decision: Decision?
    /// Shared kernel continuous seconds of the last evaluation.
    public var evaluatedAtContinuous: TimeInterval?

    public init(
        armedProfileID: UUID? = nil, activated: Bool = false, network: Network = .none, ssid: SSIDState = .notRequired,
        decision: Decision? = nil, evaluatedAtContinuous: TimeInterval? = nil,
    ) {
        self.armedProfileID = armedProfileID; self.activated = activated; self.network = network; self.ssid = ssid
        self.decision = decision; self.evaluatedAtContinuous = evaluatedAtContinuous
    }
}

/// Snapshot published by every backend (02 §4.1).
public struct TunnelStatus: Codable, Sendable, Hashable {
    /// Bound on ``recentEvents`` on every platform.
    public static let recentEventLimit = 32

    /// Status of a backend with nothing running.
    public static let idle = TunnelStatus(
        phase: .idle,
        protection: .unprotected,
        transport: nil,
        health: .idle,
        recentEvents: [],
    )

    /// Daemon-monotonic publication number; zero denotes an unmeasured local seed.
    public var sequence: UInt64 = 0
    /// Profile the daemon is currently running or attempting to run.
    public var activeProfileID: UUID?
    /// Daemon wall-clock measurement time; absent on client-generated states.
    public var measuredAt: Date?
    /// Seconds on the shared kernel continuous clock; absent on client-generated states.
    public var measuredAtContinuous: TimeInterval?
    /// Last successful policy verification; heartbeat publication never renews it.
    public var verifiedAt: Date?
    /// Shared kernel time of the last successful policy verification.
    public var verifiedAtContinuous: TimeInterval?
    /// Historical daemon report time retained when a local unavailable snapshot has no measurement.
    public var lastReportedAt: Date?
    /// Heartbeat liveness, independent of policy freshness.
    public var serviceResponding = false
    /// The service responds but policy verification has aged out.
    public var verificationExpired = false
    /// Whether a daemon operation is still pending.
    public var operationInFlight = false
    /// Whether the daemon currently enforces a WGEX packet-filter policy.
    public var policyEnforcing = false
    /// Local reporting gap, preserving the original daemon measurement time for copy.
    public var notReportingSince: Date?
    /// Local invalidation marker; no protection claim can be made from this snapshot.
    public var reportingUnavailable = false

    /// An unmeasured launch seed, with no claim about protection.
    public static var unreported: TunnelStatus {
        var status = idle
        status.protection = .unknown
        return status
    }

    /// Lifecycle phase.
    public var phase: TunnelPhase
    /// Protection state (ADR-009).
    public var protection: ProtectionState
    /// Active transport, if any.
    public var transport: TransportID?
    /// Health.
    public var health: TunnelHealth
    /// Startup recovery failure, absent after successful reconciliation.
    public var recoveryFailureReason: RecoveryFailureReason?
    /// A non-fatal limitation of the current verified protection.
    public var protectionNote: ProtectionNote?
    /// Mac cutover trial; absent on other backends and legacy snapshots.
    public var cutover: CutoverState?
    /// Fixed rollback step names, including recovered transient failures.
    public var cutoverRollbackFailures: [String] = []
    /// Mac on-demand state; nil from backends without on-demand.
    public var onDemand: OnDemandStatus?
    /// Excluded host names the last resolution could not look up; their traffic stays in the tunnel (DEC-087 warning).
    public var unresolvedExclusions: [String] = []
    /// Port exclusions this backend ignores (NetworkExtension devices, DEC-126), canonical text; shown with
    /// `UserStrings.exclusionPortsUnsupported`. Empty on the Mac, which applies them.
    public var unsupportedExclusionPorts: [String] = []
    /// Address and host-name exclusions this backend does not apply because Force all traffic is on (iPhone and iPad,
    /// M08-R01 F2), canonical text; shown with `UserStrings.exclusionsForceAllTraffic`. Empty elsewhere.
    public var forceAllIgnoredExclusions: [String] = []
    /// Most recent events, oldest first, at most ``recentEventLimit``.
    public private(set) var recentEvents: [TunnelEvent]

    /// Creates a status; `recentEvents` is trimmed to the newest ``recentEventLimit``.
    public init(
        phase: TunnelPhase,
        protection: ProtectionState,
        transport: TransportID?,
        health: TunnelHealth,
        recentEvents: [TunnelEvent],
        recoveryFailureReason: RecoveryFailureReason? = nil,
        protectionNote: ProtectionNote? = nil,
    ) {
        self.recoveryFailureReason = recoveryFailureReason
        self.protectionNote = protectionNote
        self.phase = phase
        self.protection = protection
        self.transport = transport
        self.health = health
        self.recentEvents = Array(recentEvents.suffix(Self.recentEventLimit))
    }

    /// Decodes and re-applies the event bound.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            phase: container.decode(TunnelPhase.self, forKey: .phase),
            protection: container.decode(ProtectionState.self, forKey: .protection),
            transport: container.decodeIfPresent(TransportID.self, forKey: .transport),
            health: container.decode(TunnelHealth.self, forKey: .health),
            recentEvents: container.decode([TunnelEvent].self, forKey: .recentEvents),
            recoveryFailureReason: container.decodeIfPresent(RecoveryFailureReason.self, forKey: .recoveryFailureReason),
            protectionNote: container.decodeIfPresent(Int.self, forKey: .protectionNote).flatMap(ProtectionNote.init(rawValue:)),
        )
        cutover = try container.decodeIfPresent(CutoverState.self, forKey: .cutover)
        cutoverRollbackFailures = try container.decodeIfPresent([String].self, forKey: .cutoverRollbackFailures) ?? []
        onDemand = try container.decodeIfPresent(OnDemandStatus.self, forKey: .onDemand)
        unresolvedExclusions = try container.decodeIfPresent([String].self, forKey: .unresolvedExclusions) ?? []
        unsupportedExclusionPorts = try container.decodeIfPresent([String].self, forKey: .unsupportedExclusionPorts) ?? []
        forceAllIgnoredExclusions = try container.decodeIfPresent([String].self, forKey: .forceAllIgnoredExclusions) ?? []
        sequence = try container.decodeIfPresent(UInt64.self, forKey: .sequence) ?? 0
        activeProfileID = try container.decodeIfPresent(UUID.self, forKey: .activeProfileID)
        measuredAt = try container.decodeIfPresent(Date.self, forKey: .measuredAt)
        measuredAtContinuous = try container.decodeIfPresent(TimeInterval.self, forKey: .measuredAtContinuous)
        verifiedAt = try container.decodeIfPresent(Date.self, forKey: .verifiedAt)
        verifiedAtContinuous = try container.decodeIfPresent(TimeInterval.self, forKey: .verifiedAtContinuous)
        lastReportedAt = try container.decodeIfPresent(Date.self, forKey: .lastReportedAt)
        serviceResponding = try container.decodeIfPresent(Bool.self, forKey: .serviceResponding) ?? false
        verificationExpired = try container.decodeIfPresent(Bool.self, forKey: .verificationExpired) ?? false
        operationInFlight = try container.decodeIfPresent(Bool.self, forKey: .operationInFlight) ?? false
        policyEnforcing = try container.decodeIfPresent(Bool.self, forKey: .policyEnforcing) ?? false
        notReportingSince = try container.decodeIfPresent(Date.self, forKey: .notReportingSince)
        reportingUnavailable = try container.decodeIfPresent(Bool.self, forKey: .reportingUnavailable) ?? false
    }

    /// Appends an event, dropping the oldest beyond ``recentEventLimit``.
    public mutating func record(_ event: TunnelEvent) {
        recentEvents.append(event)
        if recentEvents.count > Self.recentEventLimit {
            recentEvents.removeFirst(recentEvents.count - Self.recentEventLimit)
        }
    }
}

public extension TunnelStatus {
    /// Policy verification can take five seconds, followed by a tick and heartbeat; twenty seconds leaves scheduling margin.
    static let policyVerificationMaximumAge: TimeInterval = 20

    /// Settled PF-backed claims require evidence; an in-flight transition reports its pending phase independently.
    var requiresPolicyVerification: Bool {
        guard policyEnforcing, !operationReportsTransition else { return false }
        switch protection {
        case .protected, .blocked, .captiveWindow: return true
        case .unprotected, .unsupported, .unknown: return false
        }
    }

    private var operationReportsTransition: Bool {
        guard operationInFlight else { return false }
        switch phase {
        case .preparing, .configuring, .reasserting, .stopping: return true
        case .idle, .active, .captiveWindow, .failed: return false
        }
    }

    /// Checks the evidence required by the current policy; callers separately check heartbeat freshness.
    func hasRequiredPolicyEvidence(at continuousNow: TimeInterval) -> Bool {
        guard requiresPolicyVerification else { return true }
        guard let verifiedAtContinuous, verifiedAt != nil else { return false }
        let age = continuousNow - verifiedAtContinuous
        return age.isFinite && (0 ..< Self.policyVerificationMaximumAge).contains(age)
    }

    /// Compares controller state, excluding publication and verification bookkeeping.
    func hasSameState(as other: TunnelStatus) -> Bool {
        phase == other.phase && protection == other.protection && transport == other.transport && health == other.health &&
            activeProfileID == other.activeProfileID && operationInFlight == other.operationInFlight && policyEnforcing == other
            .policyEnforcing &&
            recoveryFailureReason == other.recoveryFailureReason && recentEvents == other.recentEvents &&
            protectionNote == other.protectionNote &&
            cutover == other.cutover && cutoverRollbackFailures == other.cutoverRollbackFailures && onDemand == other.onDemand &&
            unresolvedExclusions == other.unresolvedExclusions && unsupportedExclusionPorts == other.unsupportedExclusionPorts &&
            forceAllIgnoredExclusions == other.forceAllIgnoredExclusions
    }
}
