// SPDX-License-Identifier: MIT

/// One row per request in the authorisation table.
public enum RequestKind: String, Codable, Sendable, Hashable, CaseIterable {
    /// ``Request/hello(clientVersion:clientBuild:)``.
    case hello
    /// ``Request/installProfile(_:)``.
    case installProfile
    /// ``Request/removeProfile(_:purgeSecrets:)``.
    case removeProfile
    /// ``Request/startIntent(profileID:transport:hasSecrets:)``.
    case startIntent
    /// Trial start with dead-man rollback.
    case startCutover
    /// Commit a trial connection.
    case confirmCutover
    /// Owner-requested trial rollback, available without a console session.
    case abortCutover
    /// ``Request/stop(profileID:reason:)``.
    case stop
    /// Stop current intent.
    case stopCurrent
    /// ``Request/selectTransport(profileID:transport:)``.
    case selectTransport
    /// ``Request/setGlobalSettings(_:)``.
    case setGlobalSettings
    /// ``Request/openCaptiveWindow(seconds:)``.
    case openCaptiveWindow
    /// Captive window extension.
    case extendCaptiveWindow
    /// Event subscription.
    case subscribeEvents
    /// ``Request/closeCaptiveWindow``.
    case closeCaptiveWindow
    /// ``Request/setStartBeforeLoginIntent(profileID:enabled:)``.
    case setStartBeforeLoginIntent
    /// Read-only bundle inspection.
    case secureInstallStatus
    /// Admin-authorised bundle repair.
    case performSecureInstall
    /// ``Request/status``.
    case status
    /// ``Request/statistics``.
    case statistics
    /// ``Request/logs(since:limit:)``.
    case logs
    /// ``Request/diagnostics(_:)``.
    case diagnostics
    /// ``Request/prepareForUpdate``.
    case prepareForUpdate
    /// ``Request/uninstall(purgeState:)``.
    case uninstall
    /// ``Request/armOnDemand(profileID:hasSecrets:)``.
    case armOnDemand
    /// ``Request/disarmOnDemand(profileID:)``.
    case disarmOnDemand
    /// ``Request/reportWiFiNetwork(_:)``.
    case reportWiFiNetwork
}
