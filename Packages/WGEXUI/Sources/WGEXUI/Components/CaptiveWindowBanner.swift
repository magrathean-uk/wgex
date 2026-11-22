// SPDX-License-Identifier: MIT

import SwiftUI

/// Mac captive window banner: a live countdown and an action to end the
/// window early (ADR-009, plan 06 §4.1).
public struct CaptiveWindowBanner: View {
    private let expires: Date
    private let fixedNow: Date?
    private let onEnd: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.wgexSurfaceVisible) private var visible
    @Environment(\.wgexDisplayDate) private var displayDate

    /// Creates a banner. Pass `now` to freeze the countdown (previews, tests);
    /// otherwise it ticks every second.
    public init(expires: Date, now: Date? = nil, onEnd: @escaping () -> Void) {
        self.expires = expires
        fixedNow = now
        self.onEnd = onEnd
    }

    /// The view body.
    public var body: some View {
        if let fixedNow = fixedNow ?? displayDate {
            content(now: fixedNow)
        } else if visible {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                content(now: context.date)
            }
        } else {
            content(now: .now)
        }
    }

    private func content(now: Date) -> some View {
        let remaining = expires.timeIntervalSince(now)
        return HStack(alignment: .center, spacing: Spacing.medium) {
            Image(systemName: "hourglass")
                .accessibilityHidden(true)
                .font(Typography.cardTitle)
                .foregroundStyle(StateColor.unprotected.color)
            VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                Text(MacStrings.captiveWindow)
                    .font(Typography.cardTitle)
                Text(CaptiveWindowCopy.message(remaining: remaining))
                    .font(Typography.body)
                    .monospacedDigit()
                    .contentTransition(reduceMotion ? .opacity : .numericText(countsDown: true))
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Self.accessibilityLabel(remaining: remaining))
            .accessibilityIdentifier("wgex.protection.captiveBanner")
            Spacer(minLength: Spacing.small)
            Button(ProtectionAction.endCaptiveWindow.title, action: onEnd)
                .buttonStyle(.glass)
                .wgexControl(.protection, "endCaptiveBanner", label: ProtectionAction.endCaptiveWindow.title)
        }
        .cardBackground()
    }

    /// "Sign-in window. Unprotected for 4 minutes 32 seconds to sign in to this network".
    public static func accessibilityLabel(remaining: TimeInterval) -> String {
        MacStrings.captiveAnnouncementPrefix + CaptiveWindowCopy.spokenMessage(remaining: remaining)
    }
}
