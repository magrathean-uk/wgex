// SPDX-License-Identifier: MIT

import Foundation

/// Error taxonomy shared by every backend. Phase-0 set; P2 adds the user-facing catalogue.
public enum TunnelError: Error, Codable, Sendable, Hashable {
    /// Another profile is already intended up (one at a time in v1).
    case anotherTunnelActive
    /// No profile with this identifier is installed.
    case profileNotFound(UUID)
    /// The profile failed validation.
    case invalidConfiguration(InvalidConfigurationReason)
    /// Another client changed this profile; reload before deciding whether to overwrite it.
    case revisionConflict
    /// A conflicting operation is already in progress.
    case busy
    /// Secrets are not available to the backend.
    case secretsUnavailable
    /// The backend (daemon or extension) cannot be reached.
    case backendUnavailable
    /// The daemon is reachable and reconciling persisted state.
    case serviceRecovering
    /// The caller is not allowed to perform the operation.
    case permissionDenied
    /// An operation exceeded its deadline.
    case timedOut
    /// The engine reported a failure code.
    case engine(code: Int32)
    /// The operation was superseded or cancelled.
    case cancelled
}

/// Finite validation reasons. Legacy wire strings are discarded rather than retained.
/// The single-string Codable shape remains readable by older daemon clients.
public enum InvalidConfigurationReason: String, Codable, Sendable, Hashable {
    /// A profile failed validation.
    case invalidProfile
    /// The requested statistics sampling interval is outside the supported range.
    case statisticsInterval
    /// More than one profile is marked to start before login; the daemon starts none (M1-02).
    case multipleBootProfiles

    /// Unknown legacy strings are mapped to the generic finite reason.
    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        self = Self(rawValue: value) ?? .invalidProfile
    }
}
