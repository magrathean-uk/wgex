// SPDX-License-Identifier: MIT

import WGEXCore

/// Ordered first-match rules: mapped by WGEXNEClient on iOS and tvOS, evaluated by the daemon on macOS (ADR-030).
public struct OnDemandRule: Sendable, Hashable {
    public enum Interface: Sendable, Hashable { case any, wifi, cellular }
    public enum Action: Sendable, Hashable { case connect, disconnect }
    public let interfaceTypeMatch: Interface
    public let ssidMatch: [String]
    public let action: Action

    public init(interfaceTypeMatch: Interface, ssidMatch: [String] = [], action: Action) {
        self.interfaceTypeMatch = interfaceTypeMatch; self.ssidMatch = ssidMatch; self.action = action
    }
}

public struct OnDemandCompilation: Sendable, Hashable {
    public enum Diagnostic: Sendable, Hashable {
        /// Cellular-only is supported solely on iOS; no rules were emitted.
        case cellularRequiresIOS
        /// tvOS applies any-interface rules without SSID matching, including wifiOnly.
        case tvOSUsesAnyInterface
        /// The macOS interface options apply only on macOS; no rules were emitted.
        case interfacesRequiresMacOS
        /// The iOS Cellular and Wi-Fi options apply only on iOS; no rules were emitted.
        case iosInterfacesRequiresIOS
    }

    public let rules: [OnDemandRule]
    public let diagnostics: [Diagnostic]
}

public enum OnDemandCompiler {
    public static func compile(_ policy: OnDemandPolicy, for platform: ProfilePlatform) -> OnDemandCompilation {
        if case .off = policy {
            return OnDemandCompilation(rules: [], diagnostics: [])
        }
        if case let .iosInterfaces(interfaces) = policy {
            return platform == .iOS ? OnDemandCompilation(rules: iosRules(interfaces), diagnostics: [])
                : OnDemandCompilation(rules: [], diagnostics: [.iosInterfacesRequiresIOS])
        }
        if case .macOS = platform {
            return compileMac(policy)
        }
        return compileMobile(policy, for: platform)
    }

    private static func compileMobile(_ policy: OnDemandPolicy, for platform: ProfilePlatform) -> OnDemandCompilation {
        if case .interfaces = policy {
            return OnDemandCompilation(rules: [], diagnostics: [.interfacesRequiresMacOS])
        }
        if case .cellularOnly = policy {
            if case .iOS = platform {
                return OnDemandCompilation(
                    rules: [OnDemandRule(interfaceTypeMatch: .cellular, action: .connect), OnDemandRule(
                        interfaceTypeMatch: .any,
                        action: .disconnect,
                    )],
                    diagnostics: [],
                )
            }
            return OnDemandCompilation(rules: [], diagnostics: [.cellularRequiresIOS])
        }
        if case .tvOS = platform {
            return OnDemandCompilation(
                rules: [OnDemandRule(interfaceTypeMatch: .any, action: .connect)],
                diagnostics: [.tvOSUsesAnyInterface],
            )
        }
        let interface: OnDemandRule.Interface
        let exceptions: [String]
        switch policy {
        case let .always(ssids): interface = .any; exceptions = ssids
        case let .wifiOnly(ssids): interface = .wifi; exceptions = ssids
        case .off, .cellularOnly, .interfaces, .iosInterfaces: return OnDemandCompilation(rules: [], diagnostics: [])
        }
        let ssids = normalised(exceptions)
        var rules: [OnDemandRule] = []
        if !ssids.isEmpty {
            rules.append(OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: ssids, action: .disconnect))
        }
        rules.append(OnDemandRule(interfaceTypeMatch: interface, action: .connect))
        // Explicit fallback disconnects a previously active tunnel when leaving the selected interface.
        if interface == .wifi {
            rules.append(OnDemandRule(interfaceTypeMatch: .any, action: .disconnect))
        }
        return OnDemandCompilation(rules: rules, diagnostics: [])
    }

    /// Normalises the legacy cases to the macOS option set (ADR-030 section 2); `.off`, `.cellularOnly` and
    /// `.iosInterfaces` have none.
    public static func macInterfaces(_ policy: OnDemandPolicy) -> OnDemandInterfaces? {
        func match(_ ssids: [String]) -> OnDemandSSIDMatch {
            ssids.isEmpty ? .anySSID : .exceptSSIDs(ssids)
        }
        switch policy {
        case .off, .cellularOnly, .iosInterfaces: return nil
        case let .always(ssids): return .wifiOrEthernet(match(ssids))
        case let .wifiOnly(ssids): return .wifiOnly(match(ssids))
        case let .interfaces(interfaces): return interfaces
        }
    }

    /// The ADR-030 section 2 table. Ethernet is an `any` rule after every Wi-Fi rule; every list ends in an `any` rule.
    private static func compileMac(_ policy: OnDemandPolicy) -> OnDemandCompilation {
        guard let interfaces = macInterfaces(policy) else {
            if case .cellularOnly = policy {
                return OnDemandCompilation(rules: [], diagnostics: [.cellularRequiresIOS])
            }
            return OnDemandCompilation(rules: [], diagnostics: [])
        }
        let connectAny = OnDemandRule(interfaceTypeMatch: .any, action: .connect)
        let disconnectAny = OnDemandRule(interfaceTypeMatch: .any, action: .disconnect)
        let connectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .connect)
        let disconnectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .disconnect)
        func wifi(_ ssids: [String], _ action: OnDemandRule.Action) -> OnDemandRule {
            OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: normalised(ssids), action: action)
        }
        let rules: [OnDemandRule] = switch interfaces {
        case .ethernetOnly: [disconnectWifi, connectAny]
        case .wifiOnly(.anySSID): [connectWifi, disconnectAny]
        case let .wifiOnly(.onlySSIDs(list)): [wifi(list, .connect), disconnectAny]
        case let .wifiOnly(.exceptSSIDs(list)): [wifi(list, .disconnect), connectWifi, disconnectAny]
        case .wifiOrEthernet(.anySSID): [connectAny]
        case let .wifiOrEthernet(.onlySSIDs(list)): [wifi(list, .connect), disconnectWifi, connectAny]
        case let .wifiOrEthernet(.exceptSSIDs(list)): [wifi(list, .disconnect), connectAny]
        }
        return OnDemandCompilation(rules: rules, diagnostics: [])
    }

    /// First-match rules for the iOS option set. Wi-Fi rules come first; a Wi-Fi + Cellular list ends in an `any` connect
    /// (the official app's any interface), and every other list ends in an `any` disconnect so a tunnel raised on a
    /// selected interface goes down when no selected interface matches. An empty SSID list is read as any SSID, because
    /// an empty `ssidMatch` matches every network downstream and an empty except list would otherwise keep the tunnel down
    /// on all Wi-Fi.
    private static func iosRules(_ interfaces: OnDemandIOSInterfaces) -> [OnDemandRule] {
        let connectAny = OnDemandRule(interfaceTypeMatch: .any, action: .connect)
        let disconnectAny = OnDemandRule(interfaceTypeMatch: .any, action: .disconnect)
        let connectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .connect)
        let disconnectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .disconnect)
        func wifi(_ ssids: [String], _ action: OnDemandRule.Action) -> OnDemandRule {
            OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: normalised(ssids), action: action)
        }
        func nonEmpty(_ match: OnDemandSSIDMatch) -> OnDemandSSIDMatch {
            switch match {
            case .anySSID: .anySSID
            case let .onlySSIDs(list): list.isEmpty ? .anySSID : match
            case let .exceptSSIDs(list): list.isEmpty ? .anySSID : match
            }
        }
        let interfaces: OnDemandIOSInterfaces = switch interfaces {
        case .cellularOnly: .cellularOnly
        case let .wifiOnly(match): .wifiOnly(nonEmpty(match))
        case let .wifiOrCellular(match): .wifiOrCellular(nonEmpty(match))
        }
        return switch interfaces {
        case .cellularOnly: [OnDemandRule(interfaceTypeMatch: .cellular, action: .connect), disconnectAny]
        case .wifiOnly(.anySSID): [connectWifi, disconnectAny]
        case let .wifiOnly(.onlySSIDs(list)): [wifi(list, .connect), disconnectAny]
        case let .wifiOnly(.exceptSSIDs(list)): [wifi(list, .disconnect), connectWifi, disconnectAny]
        case .wifiOrCellular(.anySSID): [connectAny]
        case let .wifiOrCellular(.onlySSIDs(list)): [wifi(list, .connect), disconnectWifi, connectAny]
        case let .wifiOrCellular(.exceptSSIDs(list)): [wifi(list, .disconnect), connectAny]
        }
    }

    private static func normalised(_ ssids: [String]) -> [String] {
        Array(Set(ssids)).sorted()
    }
}
