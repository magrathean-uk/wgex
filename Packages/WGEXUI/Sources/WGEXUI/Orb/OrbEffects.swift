// SPDX-License-Identifier: MIT

import SwiftUI

/// One 0.6 s glow bloom each time `trigger` changes (connect).
package struct OrbBloom: ViewModifier {
    package let trigger: Int
    package let colour: StateColor
    package let diameter: CGFloat

    package func body(content: Content) -> some View {
        content.keyframeAnimator(initialValue: 0.0, trigger: trigger) { view, glow in
            view.shadow(color: colour.color.opacity(0.6 * glow), radius: diameter * 0.18 * glow)
        } keyframes: { _ in
            LinearKeyframe(1.0, duration: OrbMotion.glowBloomDuration * 0.4)
            LinearKeyframe(0.0, duration: OrbMotion.glowBloomDuration * 0.6)
        }
    }
}

/// Slow 12 s breathing while protected; nothing otherwise.
package struct OrbBreathing: ViewModifier {
    package let active: Bool

    package func body(content: Content) -> some View {
        if active {
            content.phaseAnimator([1.0, OrbMotion.breathingScale]) { view, scale in
                view.scaleEffect(scale)
            } animation: { _ in
                .easeInOut(duration: OrbMotion.breathingPeriod / 2)
            }
        } else {
            content
        }
    }
}

/// Haptics on iOS only (plan 06 §3): impact on tap, success on connect,
/// warning on blocked and on unprotected unless user-initiated.
package struct OrbFeedback: ViewModifier {
    package let presentation: ProtectionPresentation
    package let tapCount: Int

    package func body(content: Content) -> some View {
        #if os(iOS)
            content
                .sensoryFeedback(.impact, trigger: tapCount)
                .sensoryFeedback(trigger: presentation) { old, new in
                    OrbMotion.feedback(from: old.verdict, to: new).sensoryFeedback
                }
        #else
            content
        #endif
    }
}

#if os(iOS)
    package extension FeedbackKind {
        /// The iOS sensory feedback, nil for none.
        var sensoryFeedback: SensoryFeedback? {
            switch self {
            case .none: nil
            case .impact: .impact
            case .success: .success
            case .warning: .warning
            }
        }
    }
#endif
