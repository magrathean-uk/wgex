// SPDX-License-Identifier: MIT
import WGEXDaemonProtocol

/// Connection metadata only; no daemon-provided text or secret material reaches UI copy.
public enum DaemonConnectionState: Sendable, Equatable {
    case disconnected(lastError: DaemonConnectionFailure?)
    case connecting
    case connected(daemonBuild: Int)
    case secureInstallRequired(daemonBuild: Int)
}

public enum DaemonConnectionFailure: String, Sendable {
    case unavailable, unauthorised, downgradeDetected, protocolMismatch, secretsUnavailable, secureInstallRequired

    package init(_ error: any Error) {
        switch error as? DaemonError {
        case .notAuthorised, .unauthorised: self = .unauthorised
        case .downgradeDetected: self = .downgradeDetected
        case .unsupportedProtocolVersion, .malformedMessage: self = .protocolMismatch
        case .secretsUnavailable: self = .secretsUnavailable
        case .secureInstallRequired: self = .secureInstallRequired
        default: self = .unavailable
        }
    }
}
