// SPDX-License-Identifier: MIT

import WGEXCore

/// v2 states: protected/check shield/green; connecting/hourglass/neutral;
/// reasserting/arrows/neutral; blocked/lock/orange; captive/timer/red;
/// unprotected/slashed shield/red; unknown/question/neutral. Stale adds the
/// cloud-off glyph and neutral last-known evidence. Inactive is a neutral
/// selection with no session. Unsupported remains available for tvOS.
public nonisolated extension ProtectionVerdict {
    /// Default frame chip table; ProtectionPresentation supplies the distinct never-reported label.
    var provenanceTitle: String {
        switch self {
        case .protected: UserStrings.protectionMeasured
        case .blocked: MacStrings.trafficBlocked
        case .connecting: UserStrings.protectionPending
        case .reasserting: MacStrings.reconnecting
        case .inactive: UserStrings.inactive
        case .captiveWindow, .unprotected: UserStrings.unprotected
        case .stale: MacStrings.lastKnown
        case .unsupported, .unknown: UserStrings.statusReported
        }
    }

    /// Chip-sized label.
    var chipTitle: String {
        switch self {
        case .inactive: UserStrings.inactive
        case .protected: MacStrings.protected
        case .connecting: MacStrings.connecting
        case .reasserting: MacStrings.reconnecting
        case .blocked: MacStrings.trafficBlocked
        case .captiveWindow: UserStrings.unprotected
        case .unprotected: MacStrings.unprotected
        case .unsupported: MacStrings.noKillSwitch
        case .unknown: MacStrings.unknown
        case .stale: MacStrings.lastKnown
        }
    }

    /// SF Symbol name of the core glyph (plan 06 §3: shield, slashed shield,
    /// lock, hourglass, question mark).
    var glyph: String {
        switch self {
        case .inactive: "shield"
        case .protected: "checkmark.shield"
        case .connecting: "hourglass"
        case .reasserting: "arrow.trianglehead.2.clockwise.rotate.90"
        case .blocked: "lock"
        case .captiveWindow: "timer"
        case .unprotected: "shield.slash"
        case .unsupported: "exclamationmark.shield"
        case .unknown: "questionmark.circle"
        case .stale: "icloud.slash"
        }
    }

    /// Colour token; stale and unknown are never protection colours.
    var colour: StateColor {
        switch self {
        case .protected: .protected
        case .blocked: .blocked
        case .captiveWindow, .unprotected: .unprotected
        case .connecting, .reasserting, .inactive, .unsupported, .unknown, .stale: .unknown
        }
    }
}
