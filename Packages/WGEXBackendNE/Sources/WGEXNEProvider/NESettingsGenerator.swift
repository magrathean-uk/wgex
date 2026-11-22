// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Value representation of the settings applied by the untested NE adapter.
public struct NESettings: Codable, Sendable, Hashable {
    public struct IP: Codable, Sendable, Hashable {
        public var addresses: [IPAddressRange]
        public var includedRoutes: [IPAddressRange]
        public var excludedRoutes: [IPAddressRange]
    }

    public struct DNS: Codable, Sendable, Hashable {
        public let servers: [String]
        public let searchDomains: [String]
        public let matchDomains: [String]
        public let allowFailover: Bool
    }

    public let tunnelRemoteAddress: String
    public let ipv4: IP?
    public let ipv6: IP?
    public let dns: DNS?
    public let mtu: UInt16
}

public enum NESettingsGenerator {
    /// Whether the profile's address and host-name exclusions take effect here. On iPhone and iPad, Force all traffic
    /// (`includeAllNetworks`) makes NE ignore excluded routes, so none are emitted and the provider reports them instead
    /// (M08-R01 F2). The user's Force all traffic setting is never changed.
    public static func appliesExclusions(_ profile: TunnelProfile, platform: ProfilePlatform) -> Bool {
        !(platform == .iOS && profile.protection.ios.includeAllNetworks)
    }

    /// The entries NE does not apply, for the status: every port exclusion (DEC-126), and the address and host-name
    /// entries that Force all traffic keeps from applying (empty where they apply).
    public static func ignored(_ profile: TunnelProfile, platform: ProfilePlatform) -> (ports: [String], forceAll: [String]) {
        let ports = profile.exclusions.ports.map(\.text)
        guard !appliesExclusions(profile, platform: platform) else { return (ports, []) }
        let forceAll = profile.exclusions.entries.compactMap { entry -> String? in
            if case .port = entry {
                return nil
            }
            return entry.text
        }
        return (ports, forceAll)
    }

    /// `resolvedExclusions` are the addresses the profile's excluded host names resolved to (DEC-087); with the literal
    /// exclusions they become excluded routes. Any that touch the tunnel's own addresses or DNS servers are dropped.
    /// None are emitted where `appliesExclusions` is false.
    public static func generate(
        _ profile: TunnelProfile, platform: ProfilePlatform, carrier: Bool = false, resolvedExclusions: [IPAddressRange] = [],
    ) throws -> NESettings {
        var v4 = profile.interface.addresses.filter { !$0.isIPv6 }
        var v6 = profile.interface.addresses.filter(\.isIPv6)
        let routes = profile.peers.flatMap(\.allowedIPs)
        var routes6 = routes.filter(\.isIPv6)
        if v6.isEmpty, profile.protection.ipv6Policy == .blockOutside {
            v6 = try [IPAddressRange("fdf0:7765:7800::1/128")]
            routes6 = try [IPAddressRange("::/0")]
        }
        let own = profile.interface.addresses.map(\.network) + profile.interface.dns.map(\.address)
        let resolved = resolvedExclusions.filter { address in !own.contains { $0.overlaps(address) } }
        let excluded = appliesExclusions(profile, platform: platform)
            ? profile.exclusions.effectiveRanges(resolved: resolved) : []
        let lan = platform == .tvOS && profile.protection.tv.allowLAN
            ? try [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
                "fe80::/10",
                "fc00::/7",
                "ff00::/8",
            ].map(IPAddressRange.init) : []
        let exclusions = lan + excluded.filter { !lan.contains($0) }
        // Keep the supplied interface prefixes, including /64; NE owns address application.
        v4 = Array(Set(v4)).sorted { $0.stringRepresentation < $1.stringRepresentation }
        let domains: [String] = switch profile.protection.dnsPolicy {
        case .tunnelAll: [""]
        case let .split(domains): domains
        case .systemDefault: []
        }
        return NESettings(
            tunnelRemoteAddress: "127.0.0.1",
            ipv4: v4.isEmpty ? nil : NESettings.IP(
                addresses: v4, includedRoutes: routes.filter { !$0.isIPv6 }, excludedRoutes: exclusions.filter { !$0.isIPv6 },
            ),
            ipv6: v6.isEmpty ? nil : NESettings.IP(addresses: v6, includedRoutes: routes6, excludedRoutes: exclusions.filter(\.isIPv6)),
            dns: profile.interface.dns.isEmpty ? nil : NESettings.DNS(
                servers: profile.interface.dns.map(\.stringRepresentation), searchDomains: profile.interface.searchDomains,
                matchDomains: domains, allowFailover: false,
            ),
            mtu: carrier ? min(profile.interface.mtu ?? 1280, 1420) : profile.interface.mtu ?? 1280,
        )
    }
}
