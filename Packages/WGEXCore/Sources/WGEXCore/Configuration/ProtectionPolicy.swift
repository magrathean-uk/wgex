// SPDX-License-Identifier: MIT

public struct ProtectionPolicy: Codable, Sendable, Hashable {
    public var ios: IOSProtection // includeAllNetworks, excludeLocalNetworks, excludeCellularServices, excludeAPNs,
    // excludeDeviceCommunication (all explicit; applied on NEVPNProtocol)
    public var tv: TVProtection // enforceRoutes (true), allowLAN (true; excludedRoutes for LAN prefixes)
    public var dnsPolicy: DNSPolicy // .tunnelAll | .split([String]) | .systemDefault (warns)
    public var ipv6Policy: IPv6Policy // .tunnel | .blockOutside | .allowOutside (required when the profile is v4-only with a full-tunnel
    // route)

    public init(ios: IOSProtection = .defaults, tv: TVProtection = .defaults, dnsPolicy: DNSPolicy = .tunnelAll, ipv6Policy: IPv6Policy) {
        self.ios = ios; self.tv = tv; self.dnsPolicy = dnsPolicy; self.ipv6Policy = ipv6Policy
    }
}

/// Every NEVPNProtocol flag is explicit, including the flags whose SDK defaults change.
public struct IOSProtection: Codable, Sendable, Hashable {
    /// Force all traffic is opt-in. System service exclusions and local sharing are enabled initially.
    public static let defaults = IOSProtection(
        includeAllNetworks: false, excludeLocalNetworks: true, excludeCellularServices: true,
        excludeAPNs: true, excludeDeviceCommunication: true,
    )
    public var includeAllNetworks: Bool
    public var excludeLocalNetworks: Bool
    public var excludeCellularServices: Bool
    public var excludeAPNs: Bool
    public var excludeDeviceCommunication: Bool

    public init(
        includeAllNetworks: Bool, excludeLocalNetworks: Bool, excludeCellularServices: Bool,
        excludeAPNs: Bool, excludeDeviceCommunication: Bool,
    ) {
        self.includeAllNetworks = includeAllNetworks; self.excludeLocalNetworks = excludeLocalNetworks
        self.excludeCellularServices = excludeCellularServices; self.excludeAPNs = excludeAPNs
        self.excludeDeviceCommunication = excludeDeviceCommunication
    }
}

public struct TVProtection: Codable, Sendable, Hashable {
    public static let defaults = TVProtection(enforceRoutes: true, allowLAN: true)
    public var enforceRoutes: Bool
    public var allowLAN: Bool

    public init(enforceRoutes: Bool, allowLAN: Bool) {
        self.enforceRoutes = enforceRoutes; self.allowLAN = allowLAN
    }
}

public enum DNSPolicy: Codable, Sendable, Hashable { case tunnelAll, split([String]), systemDefault }
public enum IPv6Policy: String, Codable, Sendable, Hashable { case tunnel, blockOutside, allowOutside }

public enum OnDemandPolicy: Codable, Sendable, Hashable {
    case off
    /// interfaceTypeMatch `.any`; tvOS ignores the SSID list.
    case always(exceptSSIDs: [String])
    case wifiOnly(exceptSSIDs: [String])
    /// iOS only.
    case cellularOnly
    /// macOS only (ADR-030): the Mac editor writes only `.off` or this case.
    case interfaces(OnDemandInterfaces)
    /// iOS only: the Cellular and Wi-Fi option set of the official WireGuard iOS app.
    case iosInterfaces(OnDemandIOSInterfaces)
}

/// The iOS on-demand option set of the official WireGuard iOS app: Cellular on or off and Wi-Fi on or off, with any
/// SSID, only listed SSIDs or every SSID except listed ones. Both off is `OnDemandPolicy.off`.
public enum OnDemandIOSInterfaces: Codable, Sendable, Hashable {
    /// Cellular on, Wi-Fi off.
    case cellularOnly
    /// Wi-Fi on, Cellular off.
    case wifiOnly(OnDemandSSIDMatch)
    /// Wi-Fi and Cellular on; every non-Wi-Fi interface connects.
    case wifiOrCellular(OnDemandSSIDMatch)

    /// The SSID match, absent for Cellular only.
    public var ssidMatch: OnDemandSSIDMatch? {
        switch self {
        case .cellularOnly: nil
        case let .wifiOnly(match), let .wifiOrCellular(match): match
        }
    }
}

/// The macOS on-demand option set of the official WireGuard Mac app (ADR-030 section 2).
public enum OnDemandInterfaces: Codable, Sendable, Hashable {
    /// Official "Ethernet only": every non-Wi-Fi primary interface.
    case ethernetOnly
    /// Official "Wi-Fi only".
    case wifiOnly(OnDemandSSIDMatch)
    /// Official "Wi-Fi or ethernet".
    case wifiOrEthernet(OnDemandSSIDMatch)

    /// The SSID match, absent for Ethernet only.
    public var ssidMatch: OnDemandSSIDMatch? {
        switch self {
        case .ethernetOnly: nil
        case let .wifiOnly(match), let .wifiOrEthernet(match): match
        }
    }
}

/// SSID condition of a macOS or iOS Wi-Fi option; SSIDs compare by exact, case-sensitive string equality.
public enum OnDemandSSIDMatch: Codable, Sendable, Hashable {
    case anySSID
    /// Include list.
    case onlySSIDs([String])
    /// Exclude list.
    case exceptSSIDs([String])

    /// The listed SSIDs, empty for `anySSID`.
    public var ssids: [String] {
        switch self {
        case .anySSID: []
        case let .onlySSIDs(list), let .exceptSSIDs(list): list
        }
    }
}

public extension OnDemandPolicy {
    /// Every SSID the policy names, for public-field checks.
    var namedSSIDs: [String] {
        switch self {
        case let .always(ssids), let .wifiOnly(ssids): ssids
        case let .interfaces(interfaces): interfaces.ssidMatch?.ssids ?? []
        case let .iosInterfaces(interfaces): interfaces.ssidMatch?.ssids ?? []
        case .off, .cellularOnly: []
        }
    }

    /// True when evaluation on macOS needs the current SSID (an include or exclude list).
    var requiresSSID: Bool {
        switch self {
        case let .always(ssids), let .wifiOnly(ssids): !ssids.isEmpty
        case let .interfaces(interfaces): !(interfaces.ssidMatch?.ssids.isEmpty ?? true)
        // macOS emits no rules for the iOS option set, so it never needs the SSID there.
        case .off, .cellularOnly, .iosInterfaces: false
        }
    }
}

public struct MacProfileOptions: Codable, Sendable, Hashable {
    public var startBeforeLogin: Bool
    public var autoConnectAtLogin: Bool

    public init(startBeforeLogin: Bool = false, autoConnectAtLogin: Bool = false) {
        self.startBeforeLogin = startBeforeLogin; self.autoConnectAtLogin = autoConnectAtLogin
    }
}

public enum ProfilePlatform: Sendable {
    case macOS, iOS, tvOS

    public static var current: ProfilePlatform {
        #if os(macOS)
            .macOS
        #elseif os(tvOS)
            .tvOS
        #else
            .iOS
        #endif
    }
}

public extension OnDemandPolicy {
    /// macOS starts off; on-demand is opt-in there (ADR-030).
    static func defaults(for platform: ProfilePlatform) -> OnDemandPolicy {
        switch platform { case .macOS: .off; case .iOS, .tvOS: .always(exceptSSIDs: []) }
    }
}
