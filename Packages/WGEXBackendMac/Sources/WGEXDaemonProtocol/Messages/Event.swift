// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Events the daemon pushes to subscribed clients (02 §5).
public enum Event: Codable, Sendable, Hashable {
    /// Status changed.
    case status(TunnelStatus)
    /// Delivery overflowed; resubscribe and request a measured status.
    case subscriptionLost
    /// Statistics sample.
    case statistics(TunnelStatistics)
    /// Redacted log line.
    case log(RedactedLogLine)
    /// The daemon needs secrets for a profile (CLI start without stored secrets).
    case needsSecrets(profileID: UUID)
    /// The daemon asks eligible reporters for a fresh Wi-Fi reading of this interface (ADR-030 section 3).
    case wifiNetworkRequested(interfaceName: String)
}
