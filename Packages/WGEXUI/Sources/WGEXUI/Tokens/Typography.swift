// SPDX-License-Identifier: MIT

import SwiftUI

/// SF Pro Dynamic Type styles only (plan 06 §2); no fixed point sizes except
/// the orb glyph, which scales with the orb diameter.
public nonisolated enum Typography {
    /// State headline beside or under the orb.
    public static let stateTitle = Font.title2.weight(.semibold)
    /// Evidence or consequence line.
    public static let stateDetail = Font.subheadline
    /// Card and step titles.
    public static let cardTitle = Font.headline
    /// Body copy.
    public static let body = Font.body
    /// Field labels and captions.
    public static let caption = Font.caption
    /// Chip labels.
    public static let chip = Font.subheadline.weight(.semibold)
    /// Counters and rates; always used with monospaced digits.
    public static let counter = Font.title3.weight(.medium).monospacedDigit()
    /// Timestamps in lists.
    public static let timestamp = Font.caption.monospacedDigit()
    /// Keys, addresses and endpoints.
    public static let code = Font.body.monospaced()
}
