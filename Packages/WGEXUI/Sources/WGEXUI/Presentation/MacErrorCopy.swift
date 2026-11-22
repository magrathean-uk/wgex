// SPDX-License-Identifier: MIT

import WGEXCore

/// Workflow refusals whose recovery differs from a generic daemon permission error.
public nonisolated enum MacWorkflowError: Error, Sendable {
    /// Boot connection requires a verified secure install.
    case secureInstallRequired
    /// Another app transaction is still saving.
    case operationInProgress
    /// An import source could not be read or decoded.
    case importSource
    /// The app-wide login entry could not be updated.
    case loginItem
    /// A standalone fake app contains no example fixture resource.
    case fixtureUnavailable
    /// Deletion requires the current generation or blocking failure to be stopped first.
    case deletionBlocked
}

/// Safe user-facing failure copy; associated error payloads never enter the message.
public nonisolated struct MacErrorCopy: Sendable, Equatable {
    /// Failure heading.
    public let title: String
    /// What the failed operation means for the user.
    public let consequence: String
    /// A concrete recovery action.
    public let action: String
    /// Complete accessible toast or alert text.
    public var message: String {
        title + ". " + consequence + " " + action
    }

    /// Stable copy rows shared by the shell and app-specific error adapters.
    public enum Kind: Sendable, CaseIterable {
        case configuration, missingProfile, secrets, service, permission, timeout, engine, cancelled, secureCancelled, hostGuard,
             importSource, unsupported, protocolMismatch, downgrade, secureRequired, busy, activeProfile, document, store, unknown,
             loginItem, fixtureUnavailable, deletionBlocked, serviceRecovering
        /// A different client accepted a newer profile revision.
        case revisionConflict
        /// Tunnel DNS protection cannot be claimed.
        case dnsUnverified
        /// Arming was refused because the profile has no on-demand rule.
        case onDemandNotConfigured
    }

    /// Looks up one complete consequence-led row.
    // One exhaustive catalogue lookup: new cases must supply all three copy fields.
    // swiftlint:disable:next cyclomatic_complexity
    public init(_ kind: Kind, protection: ProtectionState? = nil) {
        let row: (String, String, String) = switch kind {
        case .deletionBlocked: (MacStrings.deletionBlockedTitle, MacStrings.deletionBlockedConsequence, MacStrings.deletionBlockedAction)
        case .loginItem: (MacStrings.loginItemTitle, MacStrings.loginItemConsequence, MacStrings.loginItemAction)
        case .fixtureUnavailable: (
                MacStrings.fixtureUnavailableTitle,
                MacStrings.fixtureUnavailableConsequence,
                MacStrings.fixtureUnavailableAction,
            )
        case .configuration: (MacStrings.configurationTitle, MacStrings.configurationConsequence, MacStrings.configurationAction)
        case .missingProfile: (MacStrings.missingProfileTitle, MacStrings.missingProfileConsequence, MacStrings.missingProfileAction)
        case .secrets: (MacStrings.secretsTitle, MacStrings.secretsConsequence, MacStrings.secretsAction)
        case .service: (MacStrings.serviceTitle, MacStrings.serviceConsequence, MacStrings.serviceAction)
        case .serviceRecovering: (
                MacStrings.serviceRecoveringTitle,
                protection == .blocked ? MacStrings.serviceRecoveringConsequence :
                    (protection == .unprotected ? MacStrings.trafficCanLeaveOutsideTheTunnel : MacStrings.serviceRecoveringUnmeasured),
                MacStrings.serviceRecoveringAction,
            )
        case .revisionConflict: (
                MacStrings.revisionConflictTitle,
                MacStrings.revisionConflictConsequence,
                MacStrings.revisionConflictAction,
            )
        case .dnsUnverified: (MacStrings.dnsUnverifiedTitle, MacStrings.dnsUnverifiedConsequence, MacStrings.dnsUnverifiedAction)
        case .onDemandNotConfigured: MacStrings.onDemandNotConfiguredRow
        case .permission: (MacStrings.permissionTitle, MacStrings.permissionConsequence, MacStrings.permissionAction)
        case .timeout: (MacStrings.timeoutTitle, MacStrings.timeoutConsequence, MacStrings.timeoutAction)
        case .engine: (MacStrings.engineTitle, MacStrings.engineConsequence, MacStrings.engineAction)
        case .cancelled: (MacStrings.cancelledTitle, MacStrings.cancelledConsequence, MacStrings.cancelledAction)
        case .secureCancelled: (MacStrings.secureCancelledTitle, MacStrings.secureCancelledConsequence, MacStrings.secureCancelledAction)
        case .hostGuard: (MacStrings.hostGuardTitle, MacStrings.hostGuardConsequence, MacStrings.hostGuardAction)
        case .unsupported: (MacStrings.unsupportedTitle, MacStrings.unsupportedConsequence, MacStrings.unsupportedAction)
        case .protocolMismatch: (
                MacStrings.protocolMismatchTitle,
                MacStrings.protocolMismatchConsequence,
                MacStrings.protocolMismatchAction,
            )
        case .downgrade: (MacStrings.downgradeTitle, MacStrings.downgradeConsequence, MacStrings.downgradeAction)
        case .secureRequired: (MacStrings.secureRequiredTitle, MacStrings.secureRequiredConsequence, MacStrings.secureRequiredAction)
        case .busy: (MacStrings.busyTitle, MacStrings.busyConsequence, MacStrings.busyAction)
        case .activeProfile: (MacStrings.activeProfileTitle, MacStrings.activeProfileConsequence, MacStrings.activeProfileAction)
        case .document: (MacStrings.documentTitle, MacStrings.documentConsequence, MacStrings.documentAction)
        case .store: (MacStrings.storeTitle, MacStrings.storeConsequence, MacStrings.storeAction)
        case .unknown: (MacStrings.unknownTitle, MacStrings.unknownConsequence, MacStrings.unknownAction)
        case .importSource: (MacStrings.importSourceTitle, MacStrings.importSourceConsequence, MacStrings.importSourceAction)
        }
        title = row.0
        consequence = row.1
        action = row.2
    }

    /// Maps shared errors exhaustively; unknown errors use fixed copy without interpolation.
    public init(error: any Error) {
        if let error = error as? TunnelError {
            self.init(tunnel: error)
        } else if let error = error as? ServiceError {
            self.init(service: error)
        } else if let error = error as? MacWorkflowError {
            let kind: Kind = switch error {
            case .secureInstallRequired: .secureRequired
            case .operationInProgress: .busy
            case .importSource: .importSource
            case .loginItem: .loginItem
            case .fixtureUnavailable: .fixtureUnavailable
            case .deletionBlocked: .deletionBlocked
            }
            self.init(kind)
        } else {
            self.init(.unknown)
        }
    }

    /// Exhaustive shared tunnel taxonomy.
    // Each finite error must select a fixed catalogue row.
    // swiftlint:disable:next cyclomatic_complexity
    public init(tunnel: TunnelError) {
        let kind: Kind = switch tunnel {
        case .anotherTunnelActive: .activeProfile
        case .profileNotFound: .missingProfile
        case .invalidConfiguration: .configuration
        case .secretsUnavailable: .secrets
        case .backendUnavailable: .service
        case .serviceRecovering: .serviceRecovering
        case .revisionConflict: .revisionConflict
        case .busy: .busy
        case .permissionDenied: .permission
        case .timedOut: .timeout
        case .engine: .engine
        case .cancelled: .cancelled
        }
        self.init(kind)
    }

    /// Exhaustive shared service taxonomy.
    public init(service: ServiceError) {
        let kind: Kind = switch service {
        case .hostGuard: .hostGuard
        case .system: .service
        case .unsupported: .unsupported
        }
        self.init(kind)
    }
}
