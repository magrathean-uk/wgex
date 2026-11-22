// SPDX-License-Identifier: MIT

/// iOS-specific disclosures used by shared UI and platform screens.
public nonisolated extension PlatformStrings {
    /// Copy used in the routing-policy warning sheet and the shared profile editor string facade.
    static let forceAllTraffic = "Force all traffic"
    /// Copy used in the routing-policy warning sheet.
    static let forceAllTrafficSendsEverything = "Force all traffic sends everything on this device through the tunnel, including traffic iOS normally lets bypass a VPN."
    /// Copy used in the routing-policy warning sheet.
    static let appStoreAndTestFlightUpdates = "App Store and TestFlight updates can leave this device without internet until you restart it."
    /// Copy used in the routing-policy warning sheet.
    static let whileAnUpdateInstallsTraffic = "While an update installs, traffic can leave outside the tunnel and reveal your real IP address."
    /// Copy used in the routing-policy warning sheet.
    static let withLocalNetworkAccessAllowed = "With local network access allowed, CarPlay and Personal Hotspot can stop working."
    /// Copy used in the routing-policy warning sheet.
    static let withLocalNetworkAccessBlocked = "With local network access blocked, local DNS and mDNS stop working, so local devices and names may be unreachable."
    /// Copy used in the routing-policy warning sheet.
    static let ifYouLoseInternetAfterAnUpdate = "If you lose internet after an update, restart this device. If a local service stops working, turn off Force all traffic in WGEX."
    /// Copy used in the routing-policy warning sheet and the shared profile editor string facade.
    static let thisIsARoutingPolicyNotAPromise = "This is a routing policy, not a promise of uninterrupted protection."
    /// Copy used in the shared profile editor string facade.
    static let appUpdatesCanLeaveThisPhone = "App updates can leave this phone without internet until you restart it."
    /// Copy used in the shared profile editor string facade.
    static let withLocalSharingAllowedCarPlay = "With local sharing allowed, CarPlay and Personal Hotspot can stop working."
    /// Copy used in the shared profile editor string facade.
    static let withLocalSharingBlockedLocalDN = "With local sharing blocked, local DNS and mDNS stop working. Local devices and names may be unreachable."
    /// Copy used in the shared profile editor string facade.
    static let yourRealIPAddressMayBeExposed = "Your real IP address may be exposed during app updates."
    /// Copy used in the shared profile editor string facade.
    static let phoneUpdateRecovery = "If you lose internet after an update, restart this phone. If a local service stops working, turn off Force all traffic in WGEX."
    /// Copy used in the shared profile editor string facade.
    static let excludeCellularServices = "Exclude cellular services"
    /// Copy used in the shared profile editor string facade.
    static let excludeApplePushNotifications = "Exclude Apple push notifications"
    /// Copy used in the shared profile editor string facade.
    static let excludeDeviceCommunication = "Exclude device communication"
    /// Copy used in the shared profile editor string facade.
    static let excludedServicesCanSendTraffic = "Excluded services can send traffic outside the tunnel."

    /// iPhone and iPad tunnel page (SPEC 10): the Advanced row for the interface key on an iPhone.
    static let thisIPhonesPublicKey = "This iPhone's public key"
    /// iPhone and iPad tunnel page: the Advanced row for the interface key on an iPad.
    static let thisIPadsPublicKey = "This iPad's public key"
    /// First screen: heading of the app pages group.
    static let settingsGroup = "Settings"
    /// Add a Tunnel sheet text on iPhone and iPad.
    static let addATunnelMessageIOS = "Use a WireGuard configuration made for this device. You can also open a .conf or .zip file with WGEX from Files or another app."
    /// Add a Tunnel row that opens the camera.
    static let scanQRCode = "Scan QR Code…"
    /// Add a Tunnel row that opens the paste editor.
    static let pasteConfiguration = "Paste Configuration…"
    /// Paste editor button that reads the pasted text.
    static let reviewConfiguration = "Review Configuration"
    /// Empty first screen text.
    static let addAConfigurationMadeForThisDevice = "Add a WireGuard configuration made for this device."
    /// General: exports every tunnel as one archive.
    static let exportZipArchive = "Export Zip Archive…"
    /// General: note under the archive export.
    static let exportZipArchiveNote = "Saves every tunnel, keys included, as one .zip file."
    /// General: the export could not be written.
    static let archiveCouldNotBeExported = "The archive could not be exported. Try again."
    /// General footer on iPhone and iPad.
    static let closingDoesNotDeactivateTheTunnel = "Closing WGEX does not deactivate the tunnel."
    /// Protection: note under Force all traffic.
    static let forceAllTrafficNote = "Sends traffic that iOS normally lets bypass a VPN through the tunnel."
    /// Protection: the DNS policy picker.
    static let dnsPolicy = "DNS"
    /// Protection: limit that applies on iPhone and iPad.
    static let limitRouteExclusions = "Routes the tunnel does not cover leave outside the tunnel."
    /// Log footer on iPhone and iPad, which have no diagnostics export.
    static let logFooterIOS = "Newest at the bottom."
    /// About: the bundled WireGuard engine revision.
    static let wireGuardBackend = "WireGuard backend"
    /// Review Tunnel note for a configuration without an IPv6 address.
    static let ipv6BlockedOutsideTunnel = "IPv6 traffic outside this IPv4 tunnel will be blocked by policy."
    /// Tunnel page navigation bar button that opens the editor.
    static let edit = "Edit"
    /// Tunnel page: a saved change is being applied to the running tunnel.
    static let applyingChanges = "Applying changes to the running tunnel"
    /// Tunnel editor on the grid: the visible label of a key input (its accessibility label stays "New key (base64)").
    static let editorNewKey = "New key"
    /// Tunnel editor on the grid: the placeholder of a key input.
    static let editorKeyPlaceholder = "base64"
    /// Tunnel editor on the grid: the visible title of Generate keypair (its accessibility label stays the long one).
    static let editorGenerate = "Generate"
    /// Tunnel editor on the grid: the visible label of the persistent keepalive field.
    static let editorKeepalive = "Keepalive"
    /// Tunnel editor on the grid: the unit at the end of the keepalive field.
    static let editorSeconds = "seconds"
    /// Tunnel editor on the grid: the visible title of Move peer up.
    static let editorMoveUp = "Move up"
    /// Tunnel editor on the grid: the visible title of Move peer down.
    static let editorMoveDown = "Move down"

    /// Static iOS copy covered by the catalogue tests.
    static let iosCatalogue: [String] = [
        forceAllTraffic, forceAllTrafficSendsEverything, appStoreAndTestFlightUpdates, whileAnUpdateInstallsTraffic,
        withLocalNetworkAccessAllowed, withLocalNetworkAccessBlocked, ifYouLoseInternetAfterAnUpdate, thisIsARoutingPolicyNotAPromise,
        appUpdatesCanLeaveThisPhone, withLocalSharingAllowedCarPlay, withLocalSharingBlockedLocalDN, yourRealIPAddressMayBeExposed,
        phoneUpdateRecovery, excludeCellularServices, excludeApplePushNotifications, excludeDeviceCommunication,
        excludedServicesCanSendTraffic, thisIPhonesPublicKey, thisIPadsPublicKey, settingsGroup, addATunnelMessageIOS, scanQRCode,
        pasteConfiguration, reviewConfiguration, addAConfigurationMadeForThisDevice, exportZipArchive, exportZipArchiveNote,
        archiveCouldNotBeExported, closingDoesNotDeactivateTheTunnel, forceAllTrafficNote, dnsPolicy, limitRouteExclusions,
        logFooterIOS, wireGuardBackend, applyingChanges, edit, ipv6BlockedOutsideTunnel, editorNewKey, editorKeyPlaceholder,
        editorGenerate, editorKeepalive, editorSeconds, editorMoveUp, editorMoveDown,
    ]
}
