// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Opt-in evidence gate. No shipping OS build is approved until P4-18 has a lab verdict.
public struct AppleServiceRouteTo: Sendable, Equatable {
    public let tunnel: PFInterface
    public let destinations: [IPAddressRange]
    public init?(osBuild: String, approvedBuilds: Set<String>, tunnel: PFInterface, destinations: [IPAddressRange]) {
        guard approvedBuilds.contains(osBuild), !destinations.isEmpty,
              destinations.allSatisfy({ $0.prefixLength > 0 && !$0.hasHostBits }) else { return nil }
        self.tunnel = tunnel; self.destinations = destinations.sorted()
    }
}
