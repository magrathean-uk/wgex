// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXPolicy

/// Public preferences only; persistent references identify Keychain items, never contain keys.
public struct ProtocolConfiguration: Codable, Sendable, Hashable {
    public struct Rule: Codable, Sendable, Hashable {
        public let interface: Interface
        public let ssids: [String]
        public let action: Action
    }

    public let profileID: UUID
    public let providerBundleIdentifier: String
    public let serverAddress: String
    public let passwordReference: Data?
    public let ios: IOSProtection?
    public let enforceRoutes: Bool?
    public let onDemandRules: [Rule]
}

public enum ProtocolConfigurationBuilder {
    public static func build(
        _ profile: TunnelProfile, platform: ProfilePlatform, identifiers: BuildIdentifiers = .current,
    ) -> ProtocolConfiguration {
        let reference: Data? = if case let .keychain(value) = profile.secrets.privateKey {
            value
        } else {
            nil
        }
        let rules = OnDemandCompiler.compile(profile.onDemand, for: platform).rules.map { rule in
            let interface: ProtocolConfiguration.Rule.Interface = switch rule.interfaceTypeMatch {
            case .any: .any
            case .wifi: .wifi
            case .cellular: .cellular
            }
            return ProtocolConfiguration.Rule(
                interface: interface,
                ssids: rule.ssidMatch,
                action: rule.action == .connect ? .connect : .disconnect,
            )
        }
        return ProtocolConfiguration(
            profileID: profile.id, providerBundleIdentifier: identifiers.tunnelExtension, serverAddress: "WGEX",
            passwordReference: reference, ios: platform == .iOS ? profile.protection.ios : nil,
            enforceRoutes: platform == .tvOS ? true : nil, onDemandRules: rules,
        )
    }
}

public extension ProtocolConfiguration.Rule {
    enum Interface: String, Codable, Sendable { case any, wifi, cellular }
    enum Action: String, Codable, Sendable { case connect, disconnect }
}
