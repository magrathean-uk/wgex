// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public extension DaemonFailure {
    /// Classifies only fixed wire vocabulary, preserving its binary representation.
    // Exhaustive wire taxonomy; the former CLI classifier used the same bounded exemption.
    // swiftlint:disable:next cyclomatic_complexity
    static func classify(_ wire: DaemonError) -> Code {
        switch wire {
        case .malformedMessage: .malformedMessage
        case .messageTooLarge: .messageTooLarge
        case .unsupportedProtocolVersion: .unsupportedProtocolVersion
        case .notAuthorised: .notAuthorised
        case .profileNotFound: .profileNotFound
        case .secretsUnavailable: .secretsUnavailable
        case .downgradeDetected: .downgradeDetected
        case .secureInstallRequired: .secureInstallRequired
        case let .protectionUnknown(reason):
            switch reason {
            case "underlayResolverNoAnswer": .startupResolverUnavailable
            case "captiveUnavailable": .captiveUnavailable
            case "captiveDNSFailed": .captiveDNSFailed
            case "captiveRoutesFailed": .captiveRoutesFailed
            case "captivePolicyFailed": .captivePolicyFailed
            case "canaryFailed": .pfCanaryFailed
            case "secretsHandoffDisconnected": .secretsHandoffDisconnected
            default: .protectionUnknown
            }
        case .recovering: .recovering
        case .multipleBootProfiles: .multipleBootProfiles
        case .busy: .slotRefused
        case .rateLimited: .rateLimited
        case .unauthorised: .unauthorised
        case .handshakeRequired: .handshakeRequired
        case .staleGeneration: .staleGeneration
        case .anotherTunnelActive: .anotherTunnelActive
        case .disconnected: .disconnected
        case .subscriptionLimit: .subscriptionLimit
        case .onDemandNotConfigured: .onDemandNotConfigured
        case .uninstallFailed: .uninstallFailed
        case let .tunnel(error): classify(error)
        }
    }

    /// Classifies the shared tunnel taxonomy for the same compatibility table.
    // Exhaustive shared tunnel taxonomy; every case selects one compatibility row.
    // swiftlint:disable:next cyclomatic_complexity
    static func classify(_ error: TunnelError) -> Code {
        switch error {
        case .anotherTunnelActive: .tunnelAnotherActive
        case .profileNotFound: .tunnelProfileMissing
        case .invalidConfiguration: .tunnelInvalidConfiguration
        case .revisionConflict: .tunnelRevisionConflict
        case .busy: .tunnelBusy
        case .secretsUnavailable: .tunnelSecretsUnavailable
        case .backendUnavailable: .tunnelBackendUnavailable
        case .serviceRecovering: .tunnelRecovering
        case .permissionDenied: .tunnelPermissionDenied
        case .timedOut: .tunnelTimedOut
        case .engine: .tunnelEngine
        case .cancelled: .tunnelCancelled
        }
    }
}

public extension DaemonError {
    /// Fixed shell/CLI mapping; wire payloads are retained only where already public.
    var presentation: DaemonFailurePresentation {
        let fixed = DaemonFailure.catalog[DaemonFailure.classify(self)]
        return DaemonFailurePresentation(
            self, shellError(fixed?.tunnelError ?? .backendUnavailable),
            fixed?.cliName ?? "system", fixed?.cliExitCode ?? 16,
        )
    }

    private func shellError(_ fallback: TunnelError) -> TunnelError {
        switch self {
        case let .tunnel(error): error
        case let .profileNotFound(id): .profileNotFound(id)
        default: fallback
        }
    }
}
