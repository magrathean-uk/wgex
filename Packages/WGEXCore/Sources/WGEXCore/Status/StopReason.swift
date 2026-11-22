// SPDX-License-Identifier: MIT

/// Why a tunnel stopped. Shared by `TunnelPhase.stopping` and the XPC `stop`
/// request, so it lives in `WGEXCore`.
public enum StopReason: String, Codable, Sendable, Hashable, CaseIterable {
    /// Explicit user disconnect.
    case userRequested
    /// The profile was removed.
    case profileRemoved
    /// A newer generation or another profile took over.
    case superseded
    /// The system is restarting or shutting down.
    case systemShutdown
    /// The user logged out.
    case logout
    /// The connection failed and was torn down.
    case failure
    /// The app is being updated.
    case update
    /// WGEX is being uninstalled.
    case uninstall
    /// An on-demand rule decided to disconnect (ADR-030); intent clears, secrets stay.
    case onDemand
}
