// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// What the UI says about protection right now (plan 06 §3, ADR-009). Every
/// state carries a glyph, ring and label as well as a colour.
public nonisolated enum ProtectionVerdict: String, CaseIterable, Sendable, Hashable {
    /// A selected profile that does not own the active session; no measurements.
    case inactive
    /// A verified tunnel carries traffic.
    case protected
    /// The tunnel is being established.
    case connecting
    /// An active tunnel is re-establishing after a path change, wake or switch.
    case reasserting
    /// Traffic outside the tunnel is blocked.
    case blocked
    /// Mac only: protection is suspended for a bounded sign-in window.
    case captiveWindow
    /// Traffic leaves outside the tunnel.
    case unprotected
    /// This device cannot enforce protection.
    case unsupported
    /// Protection cannot be verified; carries a reason line.
    case unknown
    /// The last status is too old to claim anything; never coloured.
    case stale
}

/// The orb ring (plan 06 §3).
public nonisolated enum RingStyle: String, CaseIterable, Sendable, Hashable {
    /// No ring.
    case none
    /// Rotating arc (or three cycling dots with Reduce Motion).
    case indeterminate
    /// Closed ring.
    case solid
    /// Dashed ring.
    case dashed
}

/// Haptic or other feedback on entering a state.
public nonisolated enum FeedbackKind: String, CaseIterable, Sendable, Hashable {
    /// No feedback.
    case none
    /// Tap or click acknowledgement.
    case impact
    /// Connection verified.
    case success
    /// Attention needed.
    case warning
}

/// The action a tap on the orb performs in a state.
public nonisolated enum ProtectionAction: String, CaseIterable, Sendable, Hashable {
    /// Start the tunnel.
    case connect
    /// Stop the tunnel.
    case disconnect
    /// Abandon a connection attempt.
    case cancel
    /// Retry after a failure.
    case reconnect
    /// Close the captive window early.
    case endCaptiveWindow
    /// Ask the backend for a fresh status.
    case checkAgain

    /// Button and accessibility title.
    public var title: String {
        switch self {
        case .connect: UserStrings.connect
        case .disconnect: UserStrings.disconnect
        case .cancel: UserStrings.cancel
        case .reconnect: UserStrings.reconnect
        case .endCaptiveWindow: UserStrings.endCaptiveWindow
        case .checkAgain: UserStrings.checkAgain
        }
    }
}

/// Why protection is unknown; becomes the unknown state's reason line.
public nonisolated enum UnknownReason: Sendable, Hashable {
    /// Verification failed (canary not hit, pf disabled, anchor missing).
    case verificationFailed
    /// The daemon or extension stopped reporting at `since`.
    case notReporting(since: Date)
    /// The VPN extension's status is unavailable.
    case extensionUnavailable
    /// Secure install has not completed (Mac).
    case secureInstallPending
    /// Network settings are still being applied (iOS, tvOS).
    case settingsPending
    /// The backend reported a state this platform cannot be in.
    case inconsistentState
    /// No reason was given.
    case unspecified
}

/// A small chip under the orb (transport or health).
public nonisolated struct OrbChip: Sendable, Hashable, Identifiable {
    /// Which chip slot this is.
    public enum Slot: String, Sendable, Hashable {
        /// Active transport; shown only when relay transports are on.
        case transport
        /// Tunnel health when it needs attention.
        case health
    }

    /// Slot, also the glass identity.
    public var slot: Slot
    /// SF Symbol name.
    public var glyph: String
    /// Visible label.
    public var title: String
    /// Colour token.
    public var colour: StateColor

    /// Creates a chip.
    public init(slot: Slot, glyph: String, title: String, colour: StateColor) {
        self.slot = slot
        self.glyph = glyph
        self.title = title
        self.colour = colour
    }

    /// Identity for lists and glass morphing.
    public var id: Slot {
        slot
    }

    /// Spoken label.
    public var accessibilityLabel: String {
        switch slot {
        case .transport: MacStrings.transportAnnouncement(String(title))
        case .health: MacStrings.health(String(title))
        }
    }
}

/// Everything a status surface shows for one status (pure value).
public nonisolated struct ProtectionPresentation: Sendable, Hashable {
    /// The verdict.
    public var verdict: ProtectionVerdict
    /// SF Symbol name of the core glyph.
    public var glyph: String
    /// Ring style.
    public var ring: RingStyle
    /// Colour token for ring, glyph and chip.
    public var colour: StateColor
    /// Primary label.
    public var primary: String
    /// Evidence or consequence line.
    public var secondary: String
    /// What a tap does.
    public var action: ProtectionAction
    /// Separate recovery explanation, never appended without punctuation.
    public var recoveryDetail: String?
    /// Service liveness; it is not a policy verification claim.
    public var reporterDetail: String?
    /// Feedback on entering this state.
    public var feedback: FeedbackKind
    /// Whether evidence is stale or unavailable; cached measurements must not be treated as current.
    public var isStale: Bool
    /// End of the captive window, when one is open.
    public var countdownExpiry: Date?
    /// Health chip, when health needs attention.
    public var healthChip: OrbChip?

    /// Creates a presentation from parts; the status mapping lives in
    /// `ProtectionPresenter.swift`.
    public init(
        verdict: ProtectionVerdict,
        glyph: String,
        ring: RingStyle,
        colour: StateColor,
        primary: String,
        secondary: String,
        action: ProtectionAction,
        feedback: FeedbackKind = .none,
        isStale: Bool = false,
        countdownExpiry: Date? = nil,
        healthChip: OrbChip? = nil,
    ) {
        self.verdict = verdict
        self.glyph = glyph
        self.ring = ring
        self.colour = colour
        self.primary = primary
        self.secondary = secondary
        self.action = action
        self.feedback = feedback
        self.isStale = isStale
        self.countdownExpiry = countdownExpiry
        self.healthChip = healthChip
    }

    /// Chip copy distinguishes no report from an unknown outcome in a received report.
    public var provenanceTitle: String {
        verdict == .unknown && isStale ? MacStrings.statusUnknown : verdict.provenanceTitle
    }

    /// VoiceOver label: state and evidence, never colour alone.
    public var accessibilityLabel: String {
        let detail = Self.joinSentences([secondary, recoveryDetail, reporterDetail].compactMap(\.self))
        let chip = healthChip.map { " " + $0.accessibilityLabel + "." } ?? ""
        return MacStrings.protectionAnnouncement(String(primary), String(detail), String(chip))
    }

    /// In-orb countdown, separate from the consequence line; never negative.
    public func countdownText(at date: Date) -> String? {
        countdownExpiry.map { UIFormat.countdown($0.timeIntervalSince(date)) }
    }

    /// A selection-only presentation, never a backend protection assertion.
    public static func inactive(activeTunnel: String) -> Self {
        Self(
            verdict: .inactive,
            glyph: ProtectionVerdict.inactive.glyph,
            ring: .none,
            colour: .unknown,
            primary: UserStrings.inactive,
            secondary: UserStrings.inactiveTunnel(active: activeTunnel),
            action: .connect,
        )
    }
}

public nonisolated extension ProtectionPresentation {
    /// Joins non-empty fragments with exactly one full stop and one intervening space.
    static func joinSentences(_ fragments: [String]) -> String {
        fragments.compactMap { fragment -> String? in
            let text = fragment.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: ".!? "))
            return text.isEmpty ? nil : text + "."
        }.joined(separator: " ")
    }
}
