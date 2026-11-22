// SPDX-License-Identifier: MIT
// Explicit module access keeps mutable bookkeeping out of the package interface.
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy
#if os(macOS)
    import SystemConfiguration
#endif

/// Classifies the configd primary interface for on-demand (ADR-030 section 2): Wi-Fi when its type is IEEE 802.11,
/// Ethernet for every other primary interface.
public protocol NetworkInterfaceClassifying: Sendable {
    func isWiFi(_ bsdName: String) -> Bool
}

/// Fixed classification for host tests; every name outside `wifi` is Ethernet.
public struct StaticInterfaceClassifier: NetworkInterfaceClassifying {
    public let wifi: Set<String>
    public init(wifi: Set<String> = []) {
        self.wifi = wifi
    }

    public func isWiFi(_ bsdName: String) -> Bool {
        wifi.contains(bsdName)
    }
}

#if os(macOS)
    /// Reads the interface type from SystemConfiguration; reads no SSID and changes no host setting.
    public struct SystemInterfaceClassifier: NetworkInterfaceClassifying {
        public init() {}

        public func isWiFi(_ bsdName: String) -> Bool {
            guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return false }
            return interfaces.contains { interface in
                SCNetworkInterfaceGetBSDName(interface) as String? == bsdName
                    && SCNetworkInterfaceGetInterfaceType(interface) == kSCNetworkInterfaceTypeIEEE80211
            }
        }
    }
#endif

/// Why the coordinator runs an evaluation (ADR-030 section 5).
package enum OnDemandTrigger: Sendable, Equatable {
    case armed
    case policyChanged(listChanged: Bool)
    case underlay
    case report
    case reporterLost
    case wake
    case consoleChanged
    case intentEnded
    case recoveryEnded
    case daemonStart
    /// An input that changes no SSID knowledge (a control command, a Lockdown change, an unchanged path) has been applied.
    case inputSettled
}

/// Named suspension points of the coordinator; host tests hold one to interleave a competing input there.
package enum OnDemandPausePoint: Sendable, Equatable {
    /// A decided action, before its admission.
    case actionDecided(OnDemandStatus.Decision)
    /// A decided action after its admission (and a start's secure-install check), before `start` or `stop`.
    case actionAdmitted(OnDemandStatus.Decision)
    /// A trigger after an invalidation, before it counts the eligible reporters.
    case askingReporters
    /// `armOnDemand` after validating the profile and its secrets, before the durable commit.
    case armValidated(UUID)
    /// A disarm, replacement, removal or override cleanup of the profile, before it stops it or deletes its secrets.
    case cleanup(UUID)
    /// A disarm, a manual disconnect's override or a removal of the profile, before its durable disarm.
    case disarming(UUID)
    /// A release the record owes, before it reads the intent it stops.
    case releasing(UUID)
    /// Reconciliation after reading the armed selection, before publishing it.
    case recoveryRead
    /// A refresh of the committed selection after its read, before publishing it.
    case selectionRead
    /// A publication in its profile's secret writes, after its registration check and before it saves the bundle.
    case publishing(UUID)
    /// A stop command after its owner lookup, before its reservation.
    case stopping(UUID)
    /// A start-before-login change of the profile, before its registry commit.
    case bootCommit(UUID)
}

/// The armed profile as the coordinator evaluates it.
internal struct ArmedOnDemand: Sendable, Equatable {
    internal let profileID: UUID
    internal let ownerUID: UInt32
    internal let policy: OnDemandPolicy
    internal let rules: [OnDemandRule]
    internal let startBeforeLogin: Bool

    internal var requiresSSID: Bool {
        rules.contains { !$0.ssidMatch.isEmpty }
    }

    internal init?(_ record: RegisteredProfile) {
        let profile = record.registration.profile
        let rules = OnDemandCompiler.compile(profile.onDemand, for: .macOS).rules
        guard !rules.isEmpty else { return nil }
        profileID = profile.id; ownerUID = record.ownerUID; policy = profile.onDemand; self.rules = rules
        startBeforeLogin = record.startBeforeLoginOverride ?? profile.macOptions.startBeforeLogin
    }
}

/// The context an on-demand decision was taken in. `start` and `stop` re-check it with no suspension before `reserve`:
/// any input since the decision (epoch), any reservation (generation), any lifecycle operation in between (operation
/// identity), a change of the armed profile, or a loss of admission (recovery, cutover, shutdown) voids the action.
internal struct OnDemandTicket: Sendable, Equatable {
    internal let epoch: UInt64
    internal let generation: Generation
    internal let operationID: UUID
    internal let profileID: UUID
}

/// A fresh SSID reading is wanted after an invalidation (ADR-030 sections 3 and 4).
internal enum OnDemandAsk: Sendable, Equatable {
    case normal
    /// Daemon start: settle for up to 10 s while the owner is the console user, even with no reporter yet.
    case startup
}

/// Armed state, SSID knowledge and settling of the on-demand coordinator (ADR-030). Lives in the controller actor, so every
/// decision is serialised with the lifecycle it drives; the SSID is held in memory only and never published.
///
/// Discipline: every input advances `epoch` synchronously, before its first await. Inputs that are applied across awaits
/// (a path change, wake, a console change, a control command) also hold evaluation in `pendingInputs` until applied, and
/// then queue a run. Decisions carry an `OnDemandTicket`; continuations whose epoch moved on do nothing, because the newer
/// input queued its own run.
internal struct OnDemandCoordinator {
    internal enum SSIDKnowledge: Sendable, Equatable {
        case known(String)
        case unavailable(OnDemandStatus.SSIDUnavailableReason)
    }

    /// Up to 3 s for a fresh report after an invalidation while a reporter is connected.
    internal static let settleSeconds = 3
    /// Up to 10 s at daemon start while the owner is the console user, so a restarting app can report first.
    internal static let startupSettleSeconds = 10

    /// The committed armed selection, set only from a registry commit at least as new as `armedVersion`.
    internal var armed: ArmedOnDemand?
    /// Registry commit version of `armed`; nil until reconciliation or a control command loaded it.
    internal var armedVersion: UInt64?
    /// Advanced synchronously by every input.
    internal var epoch: UInt64 = 0
    /// Inputs received and not yet applied; nothing is decided while any is pending.
    internal var pendingInputs = 0
    /// Set when the ticket check dropped the action in flight, so the coordinator re-evaluates on fresh state.
    internal var actionDropped = false
    /// Host tests only: runs at each named suspension point.
    internal var pause: (@Sendable (OnDemandPausePoint) async -> Void)?
    internal var ssid: SSIDKnowledge = .unavailable(.noReporter)
    /// Shared kernel continuous seconds of the last invalidation; reports observed earlier are stale.
    internal var invalidatedAt: TimeInterval = -.infinity
    /// Observation time of the last accepted report since the invalidation; an older observation never replaces it.
    internal var lastAcceptedAt: TimeInterval?
    /// A fresh reading is still to be asked for.
    internal var ask: OnDemandAsk?
    /// The epoch of the reporter count in flight, so a second run of the same epoch does not ask twice.
    internal var askingEpoch: UInt64?
    internal var settleToken: UUID?
    internal var settleTask: Task<Void, Never>?
    internal var primaryInterface: String?
    internal var evaluating = false
    internal var rerun = false
    internal var startupEvaluated = false
    internal var status: OnDemandStatus?
    internal var reporters: @Sendable () async -> Int = { 0 }
    /// Queued runs, settle timers and replays, so host tests can wait for quiescence.
    internal var scheduled: [UUID: Task<Void, Never>] = [:]

    internal var loaded: Bool {
        armedVersion != nil
    }

    internal mutating func cancelSettling() {
        settleTask?.cancel(); settleTask = nil; settleToken = nil
    }

    /// Section 3 invalidation: the held SSID and any report observed before `now` no longer count.
    internal mutating func invalidateSSID(at now: TimeInterval) {
        ssid = .unavailable(.noReporter); invalidatedAt = now; lastAcceptedAt = nil
        cancelSettling()
        epoch &+= 1
    }
}

internal extension OnDemandStatus.Network {
    var context: OnDemandNetworkContext.NetworkClass {
        switch self {
        case .none: .none
        case .ethernet: .ethernet
        case .wifi: .wifi
        }
    }
}
