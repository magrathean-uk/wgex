// SPDX-License-Identifier: MIT

/// Initial en-GB copy catalogue; plain strings until localisation infrastructure lands.
public enum UserStrings {
    /// Primary command for starting the selected connection.
    public static let connect = "Connect"
    /// Stop command shared by connection controls and notification actions.
    public static let disconnect = "Disconnect"
    /// Retry command displayed after a blocked connection failure.
    public static let reconnect = "Reconnect"
    /// Cancel action in connection, import and editor controls.
    public static let cancel = "Cancel"
    /// Primary action while a captive sign-in window is open.
    public static let endCaptiveWindow = "End Captive Window"
    /// Refresh action when the backend cannot verify protection.
    public static let checkAgain = "Check Again"
    /// Heading for the menu extra tunnel list.
    public static let tunnels = "Tunnels"
    /// Heading shared by event history and timeline navigation.
    public static let events = "Events"
    /// Toolbar command that opens the selected profile editor.
    public static let editProfile = "Edit Profile"
    /// Details grid label for the selected profile’s startup policy.
    public static let connectionAtStartup = "Connection at startup"
    /// Status label for a selected profile outside the active session.
    public static let inactive = "Inactive"
    /// Evidence chip after verified protection has been reported.
    public static let protectionMeasured = "Protection measured"
    /// Evidence chip while connection protection is being checked.
    public static let protectionPending = "Protection pending"
    /// Chip for a received unknown or unsupported protection outcome.
    public static let statusReported = "Status reported"
    /// Status heading after the reporting service becomes stale or unreachable.
    public static let serviceNotResponding = "Service not responding"

    /// Last-known evidence is never presented as current protection.
    public static func staleReport(_ age: String) -> String {
        "Last report \(age). Values shown are stale and may be wrong."
    }

    /// Selection describes a different tunnel from the current session.
    public static func inactiveTunnel(active: String) -> String {
        "Connecting this tunnel disconnects \(active) first."
    }

    public static let secretInPublicField = "A public field contains key material. Remove it before saving or importing."
    public static let protected = "Protected"
    public static let blocked = "Blocked"
    public static let captiveWindow = "Captive window"
    public static let unprotected = "Unprotected"
    public static let unsupported = "Unsupported"
    public static let unknown = "Unknown"
    public static let failed = "Failed"
    public static let secureInstallNeeded = "Secure install needed"
    public static let secretsUnavailable = "Unlock this device to make the tunnel keys available."
    public static let downgradeDetected = "This daemon is older than the installed security version. Update WGEX before connecting."
    public static let systemDNSWarning = "DNS queries may leave the tunnel when the system resolver is used."
    public static let unsupportedSchema = "This profile uses an unsupported schema version. Update WGEX before importing it."
    public static let invalidTransport = "The transport selection is invalid. Choose an available candidate and disable automatic failback."
    public static let tvProtection = "Apple TV cannot enforce a kill switch."
    public static let blockedNotificationTitle = "Traffic blocked"
    public static let blockedNotificationBody = "WGEX is blocking traffic outside the tunnel while the connection recovers."
    public static let failedNotificationTitle = "Connection failed"
    public static let failedNotificationBody = "The tunnel connection failed. Open WGEX to check whether traffic is blocked."
    public static let unknownNotificationTitle = "Protection unknown"
    public static let unknownNotificationBody = "WGEX cannot verify protection. Traffic may leave outside the tunnel. Open WGEX to check."
    public static let secureInstallNotificationBody = "Complete the secure install before WGEX can enforce protection."
    public static let openWGEX = "Open WGEX"
    /// Exclusions (DEC-087).
    public static let exclusionLimit = "A tunnel supports up to 64 exclusions. Remove some or combine addresses into a range."
    public static let exclusionDefaultRoute = "An exclusion cannot cover every address. Use a smaller range."
    public static let exclusionHostName = "An exclusion host name is invalid. Use a name such as example.com, an address or a range."
    public static let exclusionOverlapsTunnel =
        "An exclusion covers the tunnel's own address, DNS server or endpoint. Remove it or use a smaller range."
    public static let exclusionPortLimit = "A tunnel supports up to 16 port exclusions. Combine ports into a range."
    public static let exclusionPortListen = "A port exclusion covers the tunnel's own listen port. Remove it or choose another port."
    public static let exclusionPortEphemeral =
        "A port exclusion cannot cover 49152 to 65535, the range apps use for ordinary connections. Choose a port below 49152 (for example, move Transmission's 51413)."
    /// Status note where port exclusions cannot apply (NetworkExtension devices, DEC-126).
    public static func exclusionPortsUnsupported(_ ports: [String]) -> String {
        "Port exclusions \(ports.joined(separator: ", ")) are not supported on this device."
    }

    /// Status note on iPhone and iPad when Force all traffic is on: NE ignores excluded routes then (M08-R01 F2).
    public static let exclusionsForceAllTraffic = "Exclusions are not applied while Force all traffic is on."
    /// Validation warning for the same combination; the profile still saves and activates.
    public static let exclusionsForceAllTrafficWarning =
        "On iPhone and iPad, exclusions are not applied while Force all traffic is on."

    /// Warning when an excluded host name could not be resolved; its traffic stays in the tunnel.
    public static func exclusionUnresolved(_ names: [String]) -> String {
        "Could not look up \(names.joined(separator: ", ")). Traffic to \(names.count == 1 ? "it" : "them") stays in the tunnel."
    }

    /// Copy only. Notification delivery must filter user-initiated transitions and apply rate limits (P5-32).
    public static func diagnostic(_ code: ConfigDiagnostic.Code) -> String {
        diagnosticCatalogue[code] ?? "The configuration cannot be applied."
    }

    package static let diagnosticCatalogue: [ConfigDiagnostic.Code: String] = [
        .unsupportedSetting: "ignored: not supported on Apple platforms",
        .invalidDNS: "DNS must contain literal resolver addresses or valid search domains.",
        .invalidKeepalive: "PersistentKeepalive must be off or a whole number from 0 to 65535.",
        .unknownKey: "This setting is not recognised and cannot be applied.",
        .ignoredHook: "ignored: not supported on Apple platforms",
        .amneziaField: "AmneziaWG settings are incompatible with WireGuard and cannot be imported.",
        .duplicateKey: "This setting appears more than once. Keep one value before importing.",
        .duplicatePeer: "Peers must have unique public keys. Remove the duplicate peer.",
        .invalidCIDR: "The address or prefix is invalid. IPv4 prefixes must be 0 to 32 and IPv6 prefixes 0 to 128.",
        .invalidKey: "A key or its secret reference is invalid. Supply a valid 32-byte key and matching reference.",
        .invalidEndpoint: "The endpoint is invalid. Use a hostname or IP address with a port; bracket IPv6 addresses.",
        .exclusionPortEphemeral: exclusionPortEphemeral,
        .invalidPort: "The port must be between 1 and 65535.",
        .invalidMTU: "The MTU must be 1280 to 1500 on Apple platforms to support IPv6 and fit the tunnel interface.",
        .limitExceeded: "This configuration exceeds a supported limit. Reduce its size before importing.",
        .controlCharacter: "Control characters are not allowed in configuration fields. Remove them before importing.",
        .dnsOutsideAllowedIPs: "DNS traffic to a configured resolver may leave outside the tunnel because its address is outside AllowedIPs.",
        .noAddresses: "The interface needs at least one address before it can connect.",
        .noPeers: "The profile needs at least one peer before it can connect.",
        .ipv6PolicyRequired: "IPv6 traffic may leave outside this IPv4 tunnel. Choose how WGEX should handle IPv6 before connecting.",
        .keyInUseElsewhere: "This public key is already installed elsewhere. Connecting both devices may interrupt either connection.",
        .carrierRequiresSinglePeer: "Relay transports support one peer. Remove additional peers before using a relay.",
        .keepaliveClampedByCarrier: "The relay uses a keepalive interval of at most 25 seconds, increasing background traffic.",
    ]
}
