// SPDX-License-Identifier: MIT

/// Consequences and recovery actions for privilege and profile revision refusals.
public nonisolated extension MacStrings {
    /// Another client accepted a newer profile revision.
    static let revisionConflictTitle = "Tunnel changed"
    /// A stale save must not replace the newer daemon profile.
    static let revisionConflictConsequence = "Another copy of WGEX changed this tunnel; reload and try again"
    /// Recovery requires reviewing the current profile before another save.
    static let revisionConflictAction = "Review the reloaded tunnel before saving your changes."
    /// The daemon cannot support a tunnel DNS claim.
    static let dnsUnverifiedTitle = "Tunnel DNS unavailable"
    /// DNS protection is independent of the tunnel connection phase.
    static let dnsUnverifiedConsequence = "DNS is not routed through the tunnel"
    /// DNS settings must be applied and checked before claiming protection.
    static let dnsUnverifiedAction = "Review the tunnel's DNS servers, activate it again and check protection."
}
