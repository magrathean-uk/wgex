// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// One backend failure taxonomy. Only fixed codes and validated wire DTOs cross process boundaries.
/// Private detail is deliberately absent from encoding, reflection and logging.
public struct DaemonFailure: Error, Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Stable integer identifiers; append new cases, retaining existing values forever.
    public enum Code: Int, Sendable, CaseIterable {
        /// malformedMessage; never renumber or reuse.
        case malformedMessage = 1
        /// messageTooLarge; never renumber or reuse.
        case messageTooLarge = 2
        /// unsupportedProtocolVersion; never renumber or reuse.
        case unsupportedProtocolVersion = 3
        /// notAuthorised; never renumber or reuse.
        case notAuthorised = 4
        /// profileNotFound; never renumber or reuse.
        case profileNotFound = 5
        /// secretsUnavailable; never renumber or reuse.
        case secretsUnavailable = 6
        /// downgradeDetected; never renumber or reuse.
        case downgradeDetected = 7
        /// secureInstallRequired; never renumber or reuse.
        case secureInstallRequired = 8
        /// protectionUnknown; never renumber or reuse.
        case protectionUnknown = 9
        /// recovering; never renumber or reuse.
        case recovering = 10
        /// multipleBootProfiles; never renumber or reuse.
        case multipleBootProfiles = 11
        /// slotRefused; never renumber or reuse.
        case slotRefused = 12
        /// rateLimited; never renumber or reuse.
        case rateLimited = 13
        /// unauthorised; never renumber or reuse.
        case unauthorised = 14
        /// handshakeRequired; never renumber or reuse.
        case handshakeRequired = 15
        /// staleGeneration; never renumber or reuse.
        case staleGeneration = 16
        /// anotherTunnelActive; never renumber or reuse.
        case anotherTunnelActive = 17
        /// disconnected; never renumber or reuse.
        case disconnected = 18
        /// subscriptionLimit; never renumber or reuse.
        case subscriptionLimit = 19
        /// tunnelAnotherActive; never renumber or reuse.
        case tunnelAnotherActive = 30
        /// tunnelProfileMissing; never renumber or reuse.
        case tunnelProfileMissing = 31
        /// tunnelInvalidConfiguration; never renumber or reuse.
        case tunnelInvalidConfiguration = 32
        /// tunnelRevisionConflict; never renumber or reuse.
        case tunnelRevisionConflict = 33
        /// tunnelBusy; never renumber or reuse.
        case tunnelBusy = 34
        /// tunnelSecretsUnavailable; never renumber or reuse.
        case tunnelSecretsUnavailable = 35
        /// tunnelBackendUnavailable; never renumber or reuse.
        case tunnelBackendUnavailable = 36
        /// tunnelRecovering; never renumber or reuse.
        case tunnelRecovering = 37
        /// tunnelPermissionDenied; never renumber or reuse.
        case tunnelPermissionDenied = 38
        /// tunnelTimedOut; never renumber or reuse.
        case tunnelTimedOut = 39
        /// tunnelEngine; never renumber or reuse.
        case tunnelEngine = 40
        /// tunnelCancelled; never renumber or reuse.
        case tunnelCancelled = 41
        /// TunnelControllerError staleGeneration; never renumber or reuse.
        case controllerStaleGeneration = 100
        /// TunnelControllerError superseded; never renumber or reuse.
        case controllerSuperseded = 101
        /// TunnelControllerError anotherTunnelActive; never renumber or reuse.
        case controllerAnotherTunnelActive = 102
        /// TunnelControllerError invalidConfiguration; never renumber or reuse.
        case controllerInvalidConfiguration = 103
        /// TunnelControllerError secretsUnavailable; never renumber or reuse.
        case controllerSecretsUnavailable = 104
        /// TunnelControllerError operationFailed; never renumber or reuse.
        case controllerOperationFailed = 105
        /// TunnelControllerError recoveryRequired; never renumber or reuse.
        case controllerRecoveryRequired = 106
        /// TunnelControllerError notActive; never renumber or reuse.
        case controllerNotActive = 107
        /// TunnelControllerError policyVerificationFailed; never renumber or reuse.
        case controllerPolicyVerificationFailed = 108
        /// HostAdapterError labRequired; never renumber or reuse.
        case hostLabRequired = 200
        /// HostAdapterError noPrimaryInterface; never renumber or reuse.
        case hostNoPrimaryInterface = 201
        /// HostAdapterError alreadyStarted; never renumber or reuse.
        case hostAlreadyStarted = 202
        /// HostAdapterError operationInProgress; never renumber or reuse.
        case hostOperationInProgress = 203
        /// HostAdapterError unsupportedPlatform; never renumber or reuse.
        case hostUnsupportedPlatform = 204
        /// HostAdapterError unboundInterfaces; never renumber or reuse.
        case hostUnboundInterfaces = 205
        /// HostAdapterError system; never renumber or reuse.
        case hostSystem = 206
        /// HostAdapterError missingKey; never renumber or reuse.
        case hostMissingKey = 207
        /// PacketFilterFailure invalidInput; never renumber or reuse.
        case pfInvalidInput = 300
        /// PacketFilterFailure unavailable; never renumber or reuse.
        case pfUnavailable = 301
        /// PacketFilterFailure deadline; never renumber or reuse.
        case pfDeadline = 302
        /// PacketFilterFailure process; never renumber or reuse.
        case pfProcess = 303
        /// PacketFilterFailure verification; never renumber or reuse.
        case pfVerification = 304
        /// PacketFilterFailure token; never renumber or reuse.
        case pfToken = 305
        /// PacketFilterFailure journal; never renumber or reuse.
        case pfJournal = 306
        /// The sent evaluation canary did not prove enforcement.
        case pfCanaryFailed = 307
        /// StateDirectoryError unsafePath; never renumber or reuse.
        case stateUnsafePath = 400
        /// StateDirectoryError unsafeMetadata; never renumber or reuse.
        case stateUnsafeMetadata = 401
        /// StateDirectoryError tooLarge; never renumber or reuse.
        case stateTooLarge = 402
        /// StateDirectoryError system; never renumber or reuse.
        case stateSystem = 403
        /// StateDirectoryError invalidDocument; never renumber or reuse.
        case stateInvalidDocument = 404
        /// StateDirectoryError rollbackFailed; never renumber or reuse.
        case stateRollbackFailed = 405
        /// Minimum build refused; never renumber or reuse.
        case floorDowngradeDetected = 450
        /// ProfileRegistryError notFound; never renumber or reuse.
        case registryNotFound = 500
        /// ProfileRegistryError notOwner; never renumber or reuse.
        case registryNotOwner = 501
        /// ProfileRegistryError invalidProfile; never renumber or reuse.
        case registryInvalidProfile = 502
        /// ProfileRegistryError invalidSecretReference; never renumber or reuse.
        case registryInvalidSecretReference = 503
        /// ProfileRegistryError revisionConflict; never renumber or reuse.
        case registryRevisionConflict = 504
        /// ProfileRegistryError busy; never renumber or reuse.
        case registryBusy = 505
        /// ProfileRegistryError multipleBootProfiles; never renumber or reuse.
        case registryMultipleBootProfiles = 506
        /// DaemonJournalError staleGeneration; never renumber or reuse.
        case journalStaleGeneration = 550
        /// DaemonJournalError exhausted; never renumber or reuse.
        case journalExhausted = 551
        /// DaemonJournalError invalidVersion; never renumber or reuse.
        case journalInvalidVersion = 552
        /// RouteCodecError malformed; never renumber or reuse.
        case routeMalformed = 700
        /// RouteCodecError unsupported; never renumber or reuse.
        case routeUnsupported = 701
        /// RouteCodecError invalidRoute; never renumber or reuse.
        case routeInvalidRoute = 702
        /// RouteCodecError exhausted; never renumber or reuse.
        case routeExhausted = 703
        /// CaptiveWindowError closed; never renumber or reuse.
        case captiveClosed = 750
        /// CaptiveWindowError alreadyExtended; never renumber or reuse.
        case captiveAlreadyExtended = 751
        /// CaptiveWindowError invalidDuration; never renumber or reuse.
        case captiveInvalidDuration = 752
        /// CaptiveWindowError expired; never renumber or reuse.
        case captiveExpired = 753
        /// A captive window requires a live, owned tunnel.
        case captiveUnavailable = 754
        /// Owned DNS withdrawal failed before opening a window.
        case captiveDNSFailed = 755
        /// Owned route withdrawal failed before opening a window.
        case captiveRoutesFailed = 756
        /// The captive policy could not be verified.
        case captivePolicyFailed = 757
        /// WrappingKeyProvisionError accessRepairFailed; never renumber or reuse.
        case keyAccessRepairFailed = 800
        /// DaemonIntegrationError notImplemented; never renumber or reuse.
        case integrationNotImplemented = 850
        /// On-demand arming refused: the policy is `.off` or compiles to no macOS rules (ADR-030); never renumber or reuse.
        case onDemandNotConfigured = 860
        /// Uninstall step failure or refusal (`DaemonError.uninstallFailed`, M05-T07); never renumber or reuse.
        case uninstallFailed = 870
        /// startupNoPrimaryInterface; never renumber or reuse.
        case startupNoPrimaryInterface = 601
        /// startupProfileUnavailable; never renumber or reuse.
        case startupProfileUnavailable = 602
        /// startupMultipleBootProfiles; never renumber or reuse.
        case startupMultipleBootProfiles = 603
        /// startupResolverUnavailable; never renumber or reuse.
        case startupResolverUnavailable = 604
        /// startupMonitorStartFailed; never renumber or reuse.
        case startupMonitorStartFailed = 605
        /// startupReconciliationFailed; never renumber or reuse.
        case startupReconciliationFailed = 606
        /// startupIntentStartFailed; never renumber or reuse.
        case startupIntentStartFailed = 607
        /// startupBlockingPolicyFailed; never renumber or reuse.
        case startupBlockingPolicyFailed = 608
        /// startupSecureInstallRequired; never renumber or reuse.
        case startupSecureInstallRequired = 609
        /// DaemonPortError system; never renumber or reuse.
        case portSystem = 900
        /// DaemonPortError notOwned; never renumber or reuse.
        case portNotOwned = 901
        /// DaemonPortError timedOut; never renumber or reuse.
        case portTimedOut = 902
        /// DaemonPortError noAnswer; never renumber or reuse.
        case portNoAnswer = 903
        /// Code-signing information lookup failed; never renumber or reuse.
        case securitySigningInformation = 950
        /// Signing information omitted a valid hash; never renumber or reuse.
        case securityMissingHash = 951
        /// Executable is outside the expected bundle layout; never renumber or reuse.
        case securityInvalidBundleLayout = 952
        /// Executable header or architecture table is invalid; never renumber or reuse.
        case securityInvalidExecutable = 953
        /// Lab peer has no signing hash; never renumber or reuse.
        case securityLabMissingHash = 954
        /// Lab peer hash has an invalid size; never renumber or reuse.
        case securityLabInvalidHash = 955
        /// Lab peer identifier is invalid; never renumber or reuse.
        case securityLabInvalidIdentifier = 956
        /// App callback disconnected during secrets handoff; never renumber or reuse.
        case secretsHandoffDisconnected = 957
    }

    /// Fixed failure category, independent of adapter text or operating-system status.
    public let kind: Code
    /// Public stable integer identifier.
    public var code: Int {
        kind.rawValue
    }

    private let detail: String?
    private let status: Int32?
    private let wirePayload: DaemonError?

    /// Private explanatory context does not affect public failure identity or catch patterns.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.kind == rhs.kind && lhs.status == rhs.status && lhs.wirePayload == rhs.wirePayload
    }

    /// Keeps private context in process; it is never rendered or encoded.
    public init(code: Code, detail: String? = nil) {
        kind = code; self.detail = detail; status = nil; wirePayload = nil
    }

    package init(kind: Code, status: Int32) {
        self.kind = kind; self.status = status; detail = nil; wirePayload = nil
    }

    /// Numeric system result only; never an adapter's message or private detail.
    public var systemStatus: Int32? {
        status
    }

    /// Fixed integer status suitable for logs, with private context withheld.
    public var description: String {
        "DaemonFailure(\(code))"
    }

    /// Debug rendering also withholds private context.
    public var debugDescription: String {
        description
    }

    /// Reflection exposes only the stable public code.
    public var customMirror: Mirror {
        Mirror(self, children: ["code": code])
    }

    /// The existing startup status taxonomy, derived without error text.
    public var recoveryReason: RecoveryFailureReason? {
        RecoveryFailureReason(rawValue: code - 600)
    }

    /// Supports fixed-category catch patterns without reflecting any error payload.
    public static func ~= (pattern: Self, error: any Error) -> Bool {
        (error as? Self) == pattern
    }

    /// Classifies a startup failure without creating a second error type.
    public static func startup(_ reason: RecoveryFailureReason) -> Self {
        Self(code: Code(rawValue: 600 + reason.rawValue) ?? .startupReconciliationFailed)
    }

    /// An uninstall step failed, or a request met the uninstall fence; carries only the fixed step (M05-T07).
    public static func uninstall(_ step: UninstallStep) -> Self {
        Self(wire: .uninstallFailed(step: step))
    }

    /// The step an uninstall failure names; nil for every other failure.
    public var uninstallStep: UninstallStep? {
        if case let .uninstallFailed(step) = wirePayload {
            return step
        }
        return nil
    }

    /// Preserves the existing binary property-list error DTO and its public payload.
    public init(wire: DaemonError) {
        kind = Self.classify(wire); wirePayload = wire; detail = nil; status = nil
    }

    /// Projects through the catalogue; private detail can never enter the reply.
    public func wireError(profileID: UUID? = nil, protectionFailureReason: String? = nil) -> DaemonError {
        if let wirePayload {
            return wirePayload
        }
        if kind == .registryNotFound || kind == .profileNotFound {
            return .profileNotFound(profileID ?? UUID())
        }
        if let fixed = Self.catalog[kind]?.wireError {
            return fixed
        }
        if let protectionFailureReason {
            return .protectionUnknown(reason: protectionFailureReason)
        }
        return .tunnel(.backendUnavailable)
    }
}
