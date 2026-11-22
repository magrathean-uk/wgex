// SPDX-License-Identifier: MIT

/// Network context of one macOS evaluation (ADR-030 sections 2 and 4).
public struct OnDemandNetworkContext: Sendable, Hashable {
    /// Class of the configd primary interface; the WGEX utun is never classified.
    public enum NetworkClass: Sendable, Hashable { case none, ethernet, wifi }

    /// What the daemon knows of the current SSID.
    public enum SSID: Sendable, Hashable {
        case known(String)
        case unknown
    }

    public let network: NetworkClass
    public let ssid: SSID

    public init(network: NetworkClass, ssid: SSID = .unknown) {
        self.network = network; self.ssid = ssid
    }
}

/// Pure first-match evaluation of compiled macOS rules.
public enum OnDemandEvaluator {
    public enum Decision: Sendable, Hashable {
        case connect
        case disconnect
        case hold(HoldReason)
    }

    public enum HoldReason: Sendable, Hashable {
        /// No primary interface.
        case noNetwork
        /// A connect rule with a list was reached on Wi-Fi with the SSID unknown.
        case ssidUnavailable
        /// No rule matched; compiled macOS rule lists always end in an `any` rule, so this is defensive.
        case noRule
    }

    /// An unknown SSID skips a listed disconnect rule (so an unconfirmable trusted network is untrusted) and ends
    /// evaluation with `hold` at a listed connect rule (so no tunnel is raised or torn down on a guess).
    public static func evaluate(_ rules: [OnDemandRule], context: OnDemandNetworkContext) -> Decision {
        guard context.network != .none else { return .hold(.noNetwork) }
        for rule in rules {
            switch rule.interfaceTypeMatch {
            case .any: break
            case .wifi: guard context.network == .wifi else { continue }
            case .cellular: continue
            }
            if !rule.ssidMatch.isEmpty {
                guard case let .known(ssid) = context.ssid else {
                    if rule.action == .connect {
                        return .hold(.ssidUnavailable)
                    }
                    continue
                }
                guard rule.ssidMatch.contains(ssid) else { continue }
            }
            return rule.action == .connect ? .connect : .disconnect
        }
        return .hold(.noRule)
    }
}
