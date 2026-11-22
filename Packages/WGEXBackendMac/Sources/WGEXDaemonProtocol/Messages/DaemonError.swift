// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Errors carried in ``Reply/error(_:)`` and thrown by the wire codecs.
public enum DaemonError: Error, Codable, Sendable, Hashable {
    /// The message is not a valid binary property list of the expected shape.
    case malformedMessage
    /// The message exceeds ``WireCodec/maximumMessageSize``.
    case messageTooLarge(Int)
    /// The envelope's protocol version is not supported.
    case unsupportedProtocolVersion(Int)
    /// The authorisation table denied the request.
    case notAuthorised(AuthorisationDenial)
    /// The profile is not registered.
    case profileNotFound(UUID)
    /// Secrets are needed and not in the daemon store.
    case secretsUnavailable
    /// The daemon build is older than the recorded floor.
    case downgradeDetected
    /// The app bundle is writable by a non-root user.
    case secureInstallRequired
    /// Protection cannot be verified.
    case protectionUnknown(reason: String)
    /// Startup reconciliation is in progress; only recovery-safe requests are admitted.
    case recovering
    /// More than one effective boot profile is registered.
    case multipleBootProfiles
    /// A start or stop for this profile is already in flight.
    case busy
    /// The connection exceeded its request rate.
    case rateLimited
    /// The peer failed authentication or authorisation.
    case unauthorised
    /// A version handshake is required.
    case handshakeRequired
    /// A stale controller generation was supplied.
    case staleGeneration
    /// Another profile is already intended up.
    case anotherTunnelActive
    /// Transport invalidation.
    case disconnected
    /// Subscription or queue limit exceeded.
    case subscriptionLimit
    /// Arming refused: the profile's on-demand policy is off or compiles to no macOS rule (ADR-030 section 8).
    /// Additive Codable case; the protocol stays at version 8.
    case onDemandNotConfigured
    /// Uninstall (M05-T07): the step that failed or is still owed; a retry of `uninstall` resumes there. `admission` also
    /// refuses a mutating request while an uninstall is in progress or done. No adapter detail crosses the wire. Additive
    /// Codable case; the protocol stays at version 8.
    case uninstallFailed(step: UninstallStep)
    /// A tunnel error.
    case tunnel(TunnelError)
}

/// The fixed steps of `uninstall(purgeState:)`, in the order the daemon runs them (M05-T07).
public enum UninstallStep: String, Codable, Sendable, Hashable, CaseIterable {
    /// The durable fence: new starts, installs, settings and on-demand requests are refused from here on.
    case admission
    /// The active or tearing-down tunnel stops through the normal stop path with `.uninstall`.
    case stopTunnel
    /// Intent, lockdown, the captive window and the cutover record are cleared.
    case clearIntent
    /// Owned DNS configuration is removed.
    case removeDNS
    /// Owned routes are removed.
    case removeRoutes
    /// The empty (disconnected) pf policy is applied.
    case emptyPolicy
    /// The WGEX pf enable reference is released; the kill switch is off from here on.
    case releaseReference
    /// The daemon's profile registrations, with their start-before-login flags and the on-demand record.
    case daemonProfiles
    /// The daemon's sealed copies of profile secrets.
    case daemonSecrets
    /// The sealed bundles kept for on-demand and start-before-login.
    case onDemandBundles
    /// The wrapping key that sealed them.
    case wrappingKey
    /// `purgeState` only: every other state file, and the journal reduced to the uninstall marker.
    case purgeState
}

/// What `status` reports about an uninstall (M05-T07); absent when none was requested.
public struct UninstallProgress: Codable, Sendable, Hashable {
    /// Every step is done: the daemon stays inert until a fresh secure install clears the marker.
    public var completed: Bool
    /// The uninstall was asked to purge the journal and state directory.
    public var purgeState: Bool
    /// The first step still owed; nil once completed.
    public var pendingStep: UninstallStep?

    public init(completed: Bool, purgeState: Bool, pendingStep: UninstallStep?) {
        self.completed = completed; self.purgeState = purgeState; self.pendingStep = pendingStep
    }
}
