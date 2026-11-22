// SPDX-License-Identifier: MIT

/// Fixed explanations for protocol-4 startup recovery failures.
public nonisolated extension MacStrings {
    /// The primary network interface has not appeared.
    static let recoveryNoPrimaryInterface = "The primary network interface is unavailable."
    /// The persisted profile needs repair or replacement.
    static let recoveryProfileUnavailable = "The saved tunnel is missing or invalid."
    /// Underlay name resolution is unavailable.
    static let recoveryResolverUnavailable = "The peer endpoint could not be resolved."
    /// Network notifications could not be started.
    static let recoveryMonitorStartFailed = "Network monitoring could not start."
    /// Saved kernel resources could not be reconciled.
    static let recoveryReconciliationFailed = "The service could not restore its saved network state."
    /// The saved connection intent could not start.
    static let recoveryIntentStartFailed = "The saved tunnel could not start."
    /// The service cannot establish that blocking is enforced.
    static let recoveryBlockingPolicyFailed = "The recovery blocking policy could not be verified."
}
