// SPDX-License-Identifier: MIT

import Foundation

/// What the user is protected by right now (ADR-009).
public enum ProtectionState: Codable, Sendable, Hashable {
    /// Traffic flows through the tunnel.
    case protected
    /// Traffic outside the tunnel is blocked.
    case blocked
    /// A captive-portal window is open until `expires` (Mac).
    case captiveWindow(expires: Date)
    /// Traffic flows outside the tunnel.
    case unprotected
    /// The platform cannot enforce protection.
    case unsupported
    /// The state cannot be determined.
    case unknown
}
