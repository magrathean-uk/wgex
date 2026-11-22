// SPDX-License-Identifier: MIT

import Foundation
import NetworkExtension
import WGEXCore

public enum NetworkExtensionSettingsAdapter {
    public static func make(_ value: NESettings) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: value.tunnelRemoteAddress)
        if let value = value.ipv4 {
            let ipv4 = NEIPv4Settings(
                addresses: value.addresses.map(\.address),
                subnetMasks: value.addresses.map { mask($0.networkPrefixLength) },
            )
            ipv4.includedRoutes = value.includedRoutes.map { NEIPv4Route(
                destinationAddress: $0.address,
                subnetMask: mask($0.networkPrefixLength),
            ) }
            ipv4.excludedRoutes = value.excludedRoutes.map { NEIPv4Route(
                destinationAddress: $0.address,
                subnetMask: mask($0.networkPrefixLength),
            ) }
            settings.ipv4Settings = ipv4
        }
        if let value = value.ipv6 {
            let ipv6 = NEIPv6Settings(
                addresses: value.addresses.map(\.address),
                networkPrefixLengths: value.addresses.map { NSNumber(value: $0.networkPrefixLength) },
            )
            ipv6.includedRoutes = value.includedRoutes.map { NEIPv6Route(
                destinationAddress: $0.address,
                networkPrefixLength: NSNumber(value: $0.networkPrefixLength),
            ) }
            ipv6.excludedRoutes = value.excludedRoutes.map { NEIPv6Route(
                destinationAddress: $0.address,
                networkPrefixLength: NSNumber(value: $0.networkPrefixLength),
            ) }
            settings.ipv6Settings = ipv6
        }
        if let value = value.dns {
            let dns = NEDNSSettings(servers: value.servers)
            dns.searchDomains = value.searchDomains; dns.matchDomains = value.matchDomains
            dns.allowFailover = value.allowFailover
            settings.dnsSettings = dns
        }
        settings.mtu = NSNumber(value: value.mtu)
        return settings
    }

    private static func mask(_ prefix: UInt8) -> String {
        let bits = prefix == 0 ? UInt32(0) : UInt32.max << (32 - UInt32(prefix))
        return [24, 16, 8, 0].map { String((bits >> $0) & 255) }.joined(separator: ".")
    }
}
