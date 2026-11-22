// SPDX-License-Identifier: MIT
import Foundation

package enum IPv6PolicyRules {
    /// Apply the IPv6 primary after rule construction. Family-neutral underlay passes need one rule per family.
    package static func underlays(_ rules: [PFRule], primary: PFInterface, ipv6: PFInterface?) -> [PFRule] {
        guard let ipv6, ipv6 != primary else { return rules }
        return rules.flatMap { original in
            guard original.interface == primary, original.family != .ipv4 else { return [original] }
            var v6 = original; v6.interface = ipv6; v6.family = .ipv6
            // An interface-address selector follows the rule to the IPv6 underlay.
            if v6.source == .interfaceAddress(primary) {
                v6.source = .interfaceAddress(ipv6)
            }
            if v6.destination == .interfaceAddress(primary) {
                v6.destination = .interfaceAddress(ipv6)
            }
            if original.family == .ipv6 {
                return [v6]
            }
            var v4 = original; v4.family = .ipv4
            return [v4, v6]
        }
    }
}
