// SPDX-License-Identifier: MIT

/// M07-T05 seam: identifiers of the General, Protection, Background Service, Log and About pages.
/// A `requiredAtLaunch` change is a retire plus a re-add.
public nonisolated extension WGEXAccessibility {
    /// Identifiers M07-T05 adds to ``catalogue``.
    static let appPagesEntries: [Entry] = [
        Entry(screen: .service, id: "wgex.service.fact", requiredAtLaunch: false),
        Entry(screen: .settings, id: "wgex.settings.documentation", requiredAtLaunch: false),
    ]
    /// Base identifiers M07-T05 removes from ``catalogue``: the old Network rows, the Diagnostics rows, Revisit setup, the
    /// activity card's controls and the protection panel's secure install row.
    static let appPagesRetired: Set<String> = [
        "wgex.settings.allowLAN", "wgex.settings.dns", "wgex.settings.ipv6", "wgex.settings.mtu",
        "wgex.settings.logDetail", "wgex.settings.eventHistory", "wgex.settings.action",
        "wgex.events.pauseLiveUpdates", "wgex.events.showAll",
        "wgex.protection.secureInstall", "wgex.protection.secureInstallAction", "wgex.protection.serviceSettings",
    ]
}
