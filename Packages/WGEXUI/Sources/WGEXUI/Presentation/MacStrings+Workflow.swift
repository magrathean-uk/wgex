// SPDX-License-Identifier: MIT

/// Consequence-led copy for Mac workflow failures and completion actions.
public nonisolated extension MacStrings {
    /// Progress while registration is being replaced.
    static let finishingUpdate = "Finishing the update…"
    /// Replacement registration requires a new System Settings approval.
    static let needsApprovalAgain = "Needs approval again"
    /// A heartbeat proves service liveness independently of protection verification.
    static let serviceResponding = "Background service is responding"
    /// Install evidence is unavailable without a service report.
    static let secureInstallNotReporting = "The background service is not reporting its secure-install status."
    /// Recovery alone is not a protection measurement.
    static let serviceRecoveringUnmeasured = "Protection cannot be verified while the service recovers."
    /// Heading while the daemon reconciles persisted state.
    static let serviceRecoveringTitle = "Service is recovering"
    /// Recovery refuses mutations while retaining the reported blocking policy.
    static let serviceRecoveringConsequence = "The service is restoring its saved state; traffic remains blocked by the recovery policy."
    /// Recovery should finish before the user retries a mutation.
    static let serviceRecoveringAction = "Wait for recovery to finish, check the current protection state and try again."
    /// Heading for a deletion refused while another tunnel is up or traffic is blocked.
    static let deletionBlockedTitle = "Tunnel was not deleted"
    /// Another tunnel is up, or a failure keeps traffic blocked; deleting the active tunnel itself deactivates it first.
    static let deletionBlockedConsequence = "Another tunnel is active, or traffic is blocked after a failure."
    /// Recovery for deletion while a generation or blocking policy remains.
    static let deletionBlockedAction = "Deactivate it, then try deleting again."
    /// Login entry failure heading.
    static let loginItemTitle = "Login entry could not be updated"
    /// Consequence of a failed login entry update.
    static let loginItemConsequence = "Automatic login behaviour could not be updated."
    /// Recovery for the app-wide login entry.
    static let loginItemAction = "Check WGEX in System Settings → General → Login Items, then try the startup option again."
    /// Missing fake fixture heading.
    static let fixtureUnavailableTitle = "Example configuration unavailable"
    /// A missing bundle resource is an explicit fake harness limitation.
    static let fixtureUnavailableConsequence = "This fake app bundle does not contain an example configuration."
    /// A manual import is portable between build machines and guests.
    static let fixtureUnavailableAction = "Import a dedicated test configuration to use the fake backend."
    /// Heading for an unreadable import source.
    static let importSourceTitle = "Configuration could not be read"
    /// Explains per-file isolation when importing multiple sources.
    static let importSourceConsequence = "This file was skipped; other files remain available for review."
    /// Recovery guidance for a failed file import (no QR import on the Mac, D8).
    static let importSourceAction = "Choose a valid .conf or ZIP file and try again."
    /// Title for the configuration workflow outcome.
    static let configurationTitle = "Tunnel needs attention"
    /// Consequence for the configuration workflow outcome.
    static let configurationConsequence = "The tunnel cannot be used with these settings."
    /// Action for the configuration workflow outcome.
    static let configurationAction = "Review the highlighted fields and save again."
    /// Title for the missingProfile workflow outcome.
    static let missingProfileTitle = "Tunnel unavailable"
    /// Consequence for the missingProfile workflow outcome.
    static let missingProfileConsequence = "The background service no longer has this tunnel."
    /// Action for the missingProfile workflow outcome.
    static let missingProfileAction = "Import the configuration again before activating the tunnel."
    /// Title for the secrets workflow outcome.
    static let secretsTitle = "Keys unavailable"
    /// Consequence for the secrets workflow outcome.
    static let secretsConsequence = "The tunnel cannot be activated until its keys are available."
    /// Action for the secrets workflow outcome.
    static let secretsAction = "Unlock the key store or import a dedicated configuration again."
    /// Title for the service workflow outcome.
    static let serviceTitle = "Service unavailable"
    /// Consequence for the service workflow outcome.
    static let serviceConsequence = "Protection cannot be verified while the background service is unavailable."
    /// Action for the service workflow outcome.
    static let serviceAction = "Open Settings → Service, check approval and try again."
    /// Title for the permission workflow outcome.
    static let permissionTitle = "Permission needed"
    /// Consequence for the permission workflow outcome.
    static let permissionConsequence = "The requested change was not accepted."
    /// Action for the permission workflow outcome.
    static let permissionAction = "Check service approval and authorise the operation again."
    /// Title for the timeout workflow outcome.
    static let timeoutTitle = "Service did not reply"
    /// Consequence for the timeout workflow outcome.
    static let timeoutConsequence = "The result of the request could not be confirmed."
    /// Action for the timeout workflow outcome.
    static let timeoutAction = "Check the current service state before trying again."
    /// Title for the engine workflow outcome.
    static let engineTitle = "Tunnel could not start"
    /// Consequence for the engine workflow outcome.
    static let engineConsequence = "The tunnel could not be activated; check the reported protection state."
    /// Action for the engine workflow outcome.
    static let engineAction = "Review the tunnel and try activating it again."
    /// Title for the cancelled workflow outcome.
    static let cancelledTitle = "Operation cancelled"
    /// Consequence for the cancelled workflow outcome.
    static let cancelledConsequence = "The requested operation did not complete."
    /// Action for the cancelled workflow outcome.
    static let cancelledAction = "Try again when you are ready."
    /// Title for the secureCancelled workflow outcome.
    static let secureCancelledTitle = "Secure install was cancelled"
    /// Consequence for the secureCancelled workflow outcome.
    static let secureCancelledConsequence = "Secure install remains at its previous state."
    /// Action for the secureCancelled workflow outcome.
    static let secureCancelledAction = "Choose Secure Install… when you are ready to authorise it."
    /// Title for the hostGuard workflow outcome.
    static let hostGuardTitle = "VM lab required"
    /// Consequence for the hostGuard workflow outcome.
    static let hostGuardConsequence = "Background service operations are unavailable on this Mac in this build."
    /// Action for the hostGuard workflow outcome.
    static let hostGuardAction = "Use the fake backend or run this workflow in the VM lab."
    /// Title for the unsupported workflow outcome.
    static let unsupportedTitle = "Operation unavailable"
    /// Consequence for the unsupported workflow outcome.
    static let unsupportedConsequence = "This build cannot complete the requested operation."
    /// Action for the unsupported workflow outcome.
    static let unsupportedAction = "Keep the current settings and use a supported workflow."
    /// Title for the protocolMismatch workflow outcome.
    static let protocolMismatchTitle = "Service version mismatch"
    /// Consequence for the protocolMismatch workflow outcome.
    static let protocolMismatchConsequence = "The app and background service cannot exchange this request."
    /// Action for the protocolMismatch workflow outcome.
    static let protocolMismatchAction = "Install matching versions of the app and service."
    /// Title for the downgrade workflow outcome.
    static let downgradeTitle = "Older service refused"
    /// Consequence for the downgrade workflow outcome.
    static let downgradeConsequence = "The background service is older than the trusted version."
    /// Action for the downgrade workflow outcome.
    static let downgradeAction = "Install the current service from Settings → Service."
    /// Title for the secureRequired workflow outcome.
    static let secureRequiredTitle = "Secure install needed"
    /// Consequence for the secureRequired workflow outcome.
    static let secureRequiredConsequence = "The requested operation is unavailable until the app and service are secured."
    /// Action for the secureRequired workflow outcome.
    static let secureRequiredAction = "Choose Secure Install… in Settings → Service."
    /// Title for the busy workflow outcome.
    static let busyTitle = "Operation in progress"
    /// Consequence for the busy workflow outcome.
    static let busyConsequence = "The service is busy; try again in a moment"
    /// Action for the busy workflow outcome.
    static let busyAction = "Wait for the current operation and try again."
    /// Title for the activeProfile workflow outcome.
    static let activeProfileTitle = "Deactivate before changing tunnels"
    /// Consequence for the activeProfile workflow outcome.
    static let activeProfileConsequence = "A tunnel is active or changing state, so this tunnel operation was refused."
    /// Action for the activeProfile workflow outcome.
    static let activeProfileAction = "Deactivate the current tunnel, then try again."
    /// Title for the document workflow outcome.
    static let documentTitle = "Saved tunnel could not be read"
    /// Consequence for the document workflow outcome.
    static let documentConsequence = "This tunnel has been skipped; other tunnels remain available."
    /// Action for the document workflow outcome.
    static let documentAction = "Import a valid configuration to restore it."
    /// Title for the store workflow outcome.
    static let storeTitle = "Changes could not be saved"
    /// Consequence for the store workflow outcome.
    static let storeConsequence = "The local tunnel or preferences could not be written completely."
    /// Action for the store workflow outcome.
    static let storeAction = "Check available storage and access, then try again."
    /// Title for the unknown workflow outcome.
    static let unknownTitle = "Operation could not be completed"
    /// Consequence for the unknown workflow outcome.
    static let unknownConsequence = "The requested result could not be confirmed."
    /// Action for the unknown workflow outcome.
    static let unknownAction = "Check the current state and try again."
    /// Copy used by the Mac profile and service workflow.
    static let deleteProfileAction = "Delete Tunnel…"
    /// Copy used by the Mac profile and service workflow.
    static let quarantinedProfiles = "Some saved tunnels could not be read. They have been skipped; other tunnels remain available. Import valid configurations to restore them."
}
