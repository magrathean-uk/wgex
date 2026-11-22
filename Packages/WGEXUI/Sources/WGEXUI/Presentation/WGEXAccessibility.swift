// SPDX-License-Identifier: MIT

import SwiftUI

/// Automation contract: `wgex.<screen>.<element>[.<stable item ID>]`.
/// Plain camelCase element names use dns/mtu/ipv6, qrFromImage and allowLAN.
/// Repeated detail cells use stable data keys; peer cells append peer.<index>.<key>.
/// SwiftUI labels populate AXDescription; native controls may also expose AXTitle.
/// System Events should read description, falling back to title. Never use glyph names.
public nonisolated enum WGEXAccessibility {
    /// Stable screen namespaces, shared by the catalogue and hosted checks.
    public enum Screen: String, CaseIterable, Sendable {
        case main, menu, onboarding, settings, importReview, editor, export, service, profiles, protection, events, toast, connection
    }

    /// One control/status surface; repeated items append a UUID or ordered step value.
    public struct Entry: Sendable {
        /// Screen namespace.
        public let screen: Screen
        /// Full stable identifier.
        public let id: String
        /// Required even before profiles/service setup exist.
        public let requiredAtLaunch: Bool
    }

    /// Root views hosted by the VM accessibility test.
    public static let hostedScreens: [Screen] = [.main, .menu, .onboarding, .settings, .importReview]
    /// Every identifier used by the Mac UI and shared editor controls: the base list minus the identifiers M07-T04, T05 and
    /// T06 retire, plus the ones they and M08-T03 add (`WGEXAccessibility+TunnelSheets|AppPages|Setup|Exclusions.swift`).
    public static let catalogue: [Entry] = baseCatalogue.filter { !retired.contains($0.id) } + tunnelSheetsEntries + appPagesEntries +
        setupEntries + exclusionsEntries

    private static let retired = tunnelSheetsRetired.union(appPagesRetired).union(setupRetired)

    private static let baseCatalogue: [Entry] = [
        Entry(screen: .importReview, id: "wgex.importReview.ipv6", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.cancelCaptiveWindow", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.confirmCaptiveWindow", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.errorMessage", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.secureInstallAction", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.serviceSettings", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.skipFile", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.deleteProfile", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.deleteTunnel", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.confirmDelete", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.cancelDelete", requiredAtLaunch: false),
        Entry(screen: .connection, id: "wgex.connection.action", requiredAtLaunch: false),
        Entry(screen: .connection, id: "wgex.connection.chip", requiredAtLaunch: false),
        Entry(screen: .connection, id: "wgex.connection.orb", requiredAtLaunch: false),
        Entry(screen: .connection, id: "wgex.connection.verdict", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.add", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.addPeer", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.allTraffic", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.allowLAN", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.apns", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.boot", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.cancel", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.cancelChanges", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.cellular", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.clearPSK", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.communication", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.continueEditing", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.copy", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.discard", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.dnsPolicy", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.excludePrivateNetworks", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.field", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.forceAll", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.generate", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.generateKeypair", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.ipv6", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.keyInput", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.login", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.moveDown", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.moveUp", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandAddConnected", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandAddNetwork", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandEthernet", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandNetwork", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandNetworks", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandRemoveNetwork", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.onDemandWiFi", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.publicKey", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.remove", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.removePeer", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.replaceKey", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.reveal", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.save", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.splitDomains", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.validatedField", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.event", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.log", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.logView", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.pauseLiveUpdates", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.saveLog", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.showAll", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.timeline", requiredAtLaunch: false),
        Entry(screen: .events, id: "wgex.events.timelineEvent", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.cancel", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.closeSheet", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.confirm", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.confirmAll", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.done", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.exportFile", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.qr", requiredAtLaunch: false),
        Entry(screen: .export, id: "wgex.export.share", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.addresses", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.cancel", requiredAtLaunch: true),
        Entry(screen: .importReview, id: "wgex.importReview.chooseFile", requiredAtLaunch: true),
        Entry(screen: .importReview, id: "wgex.importReview.dns", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.dropTarget", requiredAtLaunch: true),
        Entry(screen: .importReview, id: "wgex.importReview.duplicate", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.endpoint", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.importAndConnect", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.importConnect", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.importLabel", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.importProfile", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.name", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.paste", requiredAtLaunch: true),
        Entry(screen: .importReview, id: "wgex.importReview.qrFromImage", requiredAtLaunch: true),
        Entry(screen: .importReview, id: "wgex.importReview.routes", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.surface", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.about", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.action", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.cancel", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.connectionCommand", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.detail", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.editProfile", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.export", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.exportAllCommand", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.importCommand", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.importFromFile", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.openCaptiveWindow", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.onDemandEdit", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.onDemandToggle", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.openBackgroundService", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.pasteConfiguration", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.profiles", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.quitCommand", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.setup", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.sheetDone", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.sidebarImport", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.startupOption", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.status", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.surface", requiredAtLaunch: true),
        Entry(screen: .main, id: "wgex.main.tunnel", requiredAtLaunch: false),
        Entry(screen: .menu, id: "wgex.menu.statusItem", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.back", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.connectionAtStartup", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.continue", requiredAtLaunch: true),
        Entry(screen: .onboarding, id: "wgex.onboarding.lockdown", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.refreshServiceState", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.registerBackgroundService", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.simulateApproval", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.step", requiredAtLaunch: true),
        Entry(screen: .onboarding, id: "wgex.onboarding.surface", requiredAtLaunch: true),
        Entry(screen: .profiles, id: "wgex.profiles.state", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.allowLocalNetwork", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.captiveBanner", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.defaultTunnel", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.endCaptiveBanner", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.endCaptiveWindow", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.killSwitch", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.lockdown", requiredAtLaunch: false),
        Entry(screen: .protection, id: "wgex.protection.secureInstall", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.finishUpdate", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.actionTitle", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.openSystemSettings", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallOpen", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallPurge", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallConfirm", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallCancel", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallRetry", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallError", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.uninstallQuit", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.secureInstall", requiredAtLaunch: false),
        Entry(screen: .service, id: "wgex.service.step", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.action", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.allowLAN", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.app", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.captiveWindow", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.closeDiagnosticsSheet", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.diagnosticsError", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.exportDiagnostics", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.exportDiagnosticsOpen", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.includeDiagnosticsLogs", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.dns", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.downgradeState", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.eventHistory", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.experimentalRelayTransports", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.firezoneSwiftComponents", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.hideDockIcon", requiredAtLaunch: true),
        Entry(screen: .settings, id: "wgex.settings.ipv6", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.logDetail", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.mtu", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.protectionNotifications", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.reRegisterBackgroundService", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.surface", requiredAtLaunch: true),
        Entry(screen: .settings, id: "wgex.settings.tab", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.wireguardapple", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.wombatvpn", requiredAtLaunch: false),
        Entry(screen: .toast, id: "wgex.toast.dismiss", requiredAtLaunch: false),
        Entry(screen: .toast, id: "wgex.toast.message", requiredAtLaunch: false),
    ]

    /// Stable keys for reusable key/address controls, independent of translated labels.
    public static func fieldKey(_ label: String) -> String {
        switch label {
        case MacStrings.privateKey: "privateKey"
        case MacStrings.presharedKey: "presharedKey"
        case MacStrings.endpoint: "endpoint"
        case MacStrings.allowedIP: "allowedIP"
        default: "address"
        }
    }
}

public extension View {
    /// Labels a status surface; voice input labels belong only to interactive controls.
    func wgexAX(_ screen: WGEXAccessibility.Screen, _ element: String, label: String, item: String? = nil) -> some View {
        accessibilityIdentifier("wgex.\(screen.rawValue).\(element)" + (item.map { "." + $0 } ?? ""))
            .accessibilityLabel(label)
    }

    /// Sets a control's automation description and a short Voice Control name.
    func wgexControl(
        _ screen: WGEXAccessibility.Screen, _ element: String, label: String, item: String? = nil, inputLabel: String? = nil,
    ) -> some View {
        wgexAX(screen, element, label: label, item: item)
            .accessibilityInputLabels([inputLabel ?? label.replacingOccurrences(of: "…", with: "")])
    }
}
