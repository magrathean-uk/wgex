// SPDX-License-Identifier: MIT

import Foundation

/// What the app read from CoreWLAN (ADR-030 section 3).
public enum WiFiReading: Codable, Sendable, Hashable {
    /// The associated network's SSID, valid UTF-8.
    case ssid(String)
    /// Location authorisation is denied, restricted or not yet granted.
    case notAuthorised
    /// CoreWLAN returned no usable SSID (redacted or not UTF-8).
    case unreadable
    /// The interface is not associated.
    case notAssociated
}

/// One Wi-Fi report from the app; the daemon accepts it only from an eligible reporter, for the current Wi-Fi primary
/// interface, observed no earlier than its last SSID invalidation.
public struct WiFiObservation: Codable, Sendable, Hashable {
    /// BSD name of the Wi-Fi interface the reading belongs to.
    public var interfaceName: String
    public var reading: WiFiReading
    /// Shared kernel continuous seconds, the clock of `TunnelStatus.measuredAtContinuous`.
    public var observedAtContinuous: TimeInterval

    public init(interfaceName: String, reading: WiFiReading, observedAtContinuous: TimeInterval) {
        self.interfaceName = interfaceName; self.reading = reading; self.observedAtContinuous = observedAtContinuous
    }

    /// Wire bounds: an interface name fits IFNAMSIZ, an SSID is 1 to 32 bytes, the time is finite.
    public var isWellFormed: Bool {
        guard (1 ... 15).contains(interfaceName.utf8.count), interfaceName.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
              observedAtContinuous.isFinite, observedAtContinuous >= 0 else { return false }
        if case let .ssid(value) = reading {
            return (1 ... 32).contains(value.utf8.count)
        }
        return true
    }
}
