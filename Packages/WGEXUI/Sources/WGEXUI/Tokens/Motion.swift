// SPDX-License-Identifier: MIT

import SwiftUI

/// One orb transition (plan 06 §3). Pure so the motion spec is testable.
public nonisolated enum OrbTransition: Sendable, Hashable {
    /// Ring spring into connecting.
    case spring(duration: Double, bounce: Double)
    /// No animation: the ring snaps (connecting to protected).
    case snap
    /// Opacity cross-fade (reasserting, and every Reduce Motion transition).
    case crossFade(duration: Double)
    /// Ring fade (into unprotected or unknown).
    case fade(duration: Double)
    /// Glyph and ring morph (into blocked and other states).
    case morph(duration: Double)

    /// The SwiftUI animation, nil for ``snap``.
    public var animation: Animation? {
        switch self {
        case let .spring(duration, bounce): .spring(duration: duration, bounce: bounce)
        case .snap: nil
        case let .crossFade(duration): .easeInOut(duration: duration)
        case let .fade(duration): .easeOut(duration: duration)
        case let .morph(duration): .smooth(duration: duration)
        }
    }
}

/// Motion constants and rules for the orb (plan 06 §3).
public nonisolated enum OrbMotion {
    /// Disconnected to connecting ring spring.
    public static let connectSpring = OrbTransition.spring(duration: 0.5, bounce: 0.2)
    /// Seconds per turn of the indeterminate ring.
    public static let rotationPeriod: TimeInterval = 1.6
    /// Glyph morph (matched geometry) duration.
    public static let glyphMorphDuration: TimeInterval = 0.4
    /// One glow bloom on connect.
    public static let glowBloomDuration: TimeInterval = 0.6
    /// Active to reasserting dashed cross-fade.
    public static let reassertCrossFade = OrbTransition.crossFade(duration: 0.25)
    /// Any to unprotected ring fade.
    public static let ringFade = OrbTransition.fade(duration: 0.3)
    /// Breathing cycle while protected.
    public static let breathingPeriod: TimeInterval = 12
    /// Breathing scale amplitude.
    public static let breathingScale: CGFloat = 1.015
    /// Reduce Motion replacement for every transition.
    public static let reducedCrossFade = OrbTransition.crossFade(duration: 0.2)
    /// Reduce Motion indeterminate indicator: one dot step per second (1 Hz).
    public static let reducedDotStep: TimeInterval = 1

    /// The transition between two verdicts.
    public static func transition(from old: ProtectionVerdict?, to new: ProtectionVerdict, reduceMotion: Bool) -> OrbTransition {
        if reduceMotion {
            return reducedCrossFade
        }
        switch new {
        case .connecting:
            return connectSpring
        case .protected:
            return old == .connecting ? .snap : .morph(duration: glyphMorphDuration)
        case .reasserting:
            return reassertCrossFade
        case .unprotected, .unknown, .stale, .inactive:
            return ringFade
        case .blocked, .captiveWindow, .unsupported:
            return .morph(duration: glyphMorphDuration)
        }
    }

    /// Feedback when the verdict changes: success on connect, warning on
    /// blocked, warning on unprotected unless the user asked for it, none on
    /// unknown (plan 06 §3).
    public static func feedback(from old: ProtectionVerdict?, to new: ProtectionPresentation) -> FeedbackKind {
        guard old != new.verdict else { return .none }
        switch new.verdict {
        case .protected:
            return old == .connecting ? .success : .none
        case .blocked, .unprotected, .captiveWindow:
            return new.feedback
        case .connecting, .reasserting, .unsupported, .unknown, .stale, .inactive:
            return .none
        }
    }

    /// Whether a transition ends with the one-off glow bloom.
    public static func blooms(from old: ProtectionVerdict?, to new: ProtectionVerdict, reduceMotion: Bool) -> Bool {
        !reduceMotion && new == .protected && (old == .connecting || old == .reasserting)
    }
}
