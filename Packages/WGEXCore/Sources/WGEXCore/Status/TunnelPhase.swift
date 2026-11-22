// SPDX-License-Identifier: MIT

import Foundation

/// Tunnel lifecycle shared by every backend (02 §4.1).
public enum TunnelPhase: Codable, Sendable, Hashable {
    /// Nothing is running.
    case idle
    /// Resolving endpoints and choosing the underlay.
    case preparing(Generation)
    /// Interface up; routes, DNS and settings being applied.
    case configuring(Generation)
    /// Settings verified and the engine running.
    case active(Generation)
    /// Path change, wake or transport switch in progress.
    case reasserting(Generation, reason: ReassertReason)
    /// Mac only: routes and DNS withdrawn, narrowed pass until `expires`.
    case captiveWindow(Generation, expires: Date)
    /// Teardown in progress.
    case stopping(Generation, reason: StopReason)
    /// Failed; `blockedByPolicy` when traffic stays blocked.
    case failed(TunnelError, blockedByPolicy: Bool, needsSecrets: Bool)

    /// Generation of the phase, if it has one.
    public var generation: Generation? {
        switch self {
        case .idle, .failed:
            nil
        case let .preparing(generation), let .configuring(generation), let .active(generation):
            generation
        case let .reasserting(generation, _), let .captiveWindow(generation, _), let .stopping(generation, _):
            generation
        }
    }
}
