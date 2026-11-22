// SPDX-License-Identifier: MIT

import Foundation

/// Settings navigation, preferences, notifications, diagnostics and updates.
public nonisolated extension MacStrings {
    /// Unified window navigation and its sole sidebar footer action.
    static let backgroundServicePage = "Background Service"
    static let logPage = "Log"
    static let addTunnel = "Add Tunnel…"
    static let sidebarBlocked = "Blocked"
    /// Copy used in Mac setup and Settings navigation and Mac Settings.
    static let general = "General"
    /// Copy used in Mac Settings.
    static let hideDockIcon = "Hide Dock icon"
    /// Copy used in Mac setup and Settings navigation and the Mac protection controls.
    static let protection = "Protection"
    /// Copy used in Mac Settings.
    static let notifications = "Notifications"
    /// Copy used in Mac Settings.
    static let notificationDeliveryArrivesInA = "Notification delivery arrives in a later update."
    /// Copy used in Mac setup and Settings navigation and Mac Settings.
    static let diagnostics = "Diagnostics"
    /// Copy used in Mac Settings.
    static let standard = "Standard"
    /// Diagnostics export sheet and its buttons.
    static let exportDiagnostics = "Export Diagnostics"
    static let exportDiagnosticsEllipsis = "Export Diagnostics…"
    static let exportEllipsis = "Export…"
    static let includeLogs = "Include logs"
    static let theArchiveHoldsTheseRedactedItems = "The archive is built by the background service. Keys, preshared keys and configuration text are removed from everything in it."
    static let diagnosticsContentRedactedLogs = "Tunnel and service log lines (only with Include logs)"
    static let diagnosticsContentFirewall = "Firewall rules the service holds"
    static let diagnosticsContentRoutes = "Routes and DNS settings"
    static let diagnosticsContentManifest = "A manifest of the files in the archive"
    static let diagnosticsContents = [
        diagnosticsContentRedactedLogs, diagnosticsContentFirewall, diagnosticsContentRoutes, diagnosticsContentManifest,
    ]
    static let diagnosticsSaved = "The diagnostics archive was saved."
    static let theDiagnosticsCouldNotBeSaved = "The diagnostics archive could not be saved. Nothing was written."
    static func diagnosticsFilename(_ stamp: String) -> String {
        "WGEX Diagnostics \(stamp)Z.zip"
    }

    /// Copy used in Mac setup and Settings navigation and Mac Settings.
    static let service = "Service"
    /// Copy used in Mac setup and Settings navigation and Mac Settings.
    static let network = "Network"
    /// Copy used in Mac Settings.
    static let automatic = "Automatic"
    /// Menu command that opens the Settings window.
    static let settingsCommand = "Settings…"
    /// Settings navigation label without the menu command ellipsis.
    static let settingsTitle = "Settings"
}
