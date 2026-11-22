// SPDX-License-Identifier: MIT
import WGEXCore

/// Reasons a daemon measurement cannot support a full protection claim.
public enum DaemonProtectionReason: String, Codable, Sendable, Hashable {
    /// No tunnel resolver has been verified as applied for this profile and generation.
    case dnsUnverified
}

/// An outward status qualified by the installed profile's actual guarantees.
public struct QualifiedDaemonStatus: Sendable {
    /// Status after withdrawing any unsupported protected claim.
    public var status: TunnelStatus
    /// Fixed vocabulary available through the owner-scoped protection-reasons request.
    public let reasons: [DaemonProtectionReason]
    /// Creates a qualification result without carrying arbitrary profile metadata.
    public init(status: TunnelStatus, reasons: [DaemonProtectionReason]) {
        self.status = status; self.reasons = reasons
    }
}
