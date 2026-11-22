// SPDX-License-Identifier: MIT

/// Fixed runtime diagnostics; no caller-supplied text or error detail may enter this port.
public enum DaemonRuntimeMessage: String, Sendable {
    /// Startup keeps administrative requests policy-checked.
    case adminRightDefinitionFailed = "Administrative right definition failed; administrative requests remain policy-checked"
    /// Missing wrapping material requires secure installation.
    case wrappingKeyUnavailable = "Wrapping key is unavailable; secure install is required before storing secrets"
    /// Owned PF references are reacquired without releasing a foreign reference.
    case externalReferenceReleased = "Owned pf enable reference was externally released; reacquiring"
    /// The monitor cannot currently verify protection.
    case networkUnknown = "Network verification failed; protection unknown"
    /// Orderly termination waits until blocking is established.
    case shutdownWaiting = "Orderly shutdown is waiting for blocking policy"
    /// Emitted only after the controller has durably checkpointed orderly shutdown.
    case shutdownComplete = "Orderly shutdown completed; checkpoint written"
    /// The prior process completed its orderly shutdown policy.
    case previousShutdownClean = "Previous daemon shutdown was orderly"
    /// An absent orderly marker does not identify why the prior process stopped.
    case previousShutdownUnrecorded = "Previous daemon shutdown was not recorded as orderly"
    /// The listener precedes startup reconciliation.
    case listeningRecovering = "Daemon listening; recovering"
    /// Incomplete fingerprint registration disables exports.
    case diagnosticRegistrationPending = "Diagnostics unavailable until installed profile registration succeeds"
    /// Verification failed without publishing adapter detail.
    case verificationUnknown = "Protection verification failed; state unknown"
    #if WGEX_LAB_BUILD
        /// DEC-013: Lab clients refuse this daemon until it publishes its own code-directory hashes.
        case labIdentityUnpublished = "Lab daemon identity was not published; Lab clients refuse this daemon"
    #endif
}
