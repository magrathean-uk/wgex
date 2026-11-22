// SPDX-License-Identifier: MIT

import WGEXCore

/// Replies from the daemon (02 §5).
public enum Reply: Codable, Sendable, Hashable {
    /// Hello reply.
    case hello(HelloReply)
    /// Success without a payload.
    case ok
    /// The daemon's accepted revision, or nil for a profile-revision lookup before creation.
    case profileRevision(UInt64?)
    /// CAS was rejected without writing; refresh before proposing another edit.
    case profileRevisionConflict(currentRevision: UInt64?)
    /// Fixed reasons qualifying the current protection claim.
    case protectionReasons([DaemonProtectionReason])
    /// Start accepted with the daemon-allocated generation.
    case started(Generation)
    /// Secure-install inspection or repair result.
    case secureInstall(SecureInstallReport)
    /// Status snapshot.
    case status(TunnelStatus)
    /// Status snapshot with its Lab telemetry.
    case statusTelemetry(StatusTelemetry)
    /// Statistics sample.
    case statistics(TunnelStatistics)
    /// Redacted log lines.
    case logs([RedactedLogLine])
    /// Diagnostics bundle.
    case diagnostics(DiagnosticsBundle)
    /// Failure.
    case error(DaemonError)
}
