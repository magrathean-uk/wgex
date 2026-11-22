// SPDX-License-Identifier: MIT

import SwiftUI

/// A measurement for ``StatTile``. Unavailable values say so; never zero.
public nonisolated enum StatValue: Sendable, Hashable {
    /// Bytes per second.
    case rate(Double)
    /// A byte count.
    case bytes(UInt64)
    /// Time since `since`, evaluated at `now`.
    case age(since: Date, now: Date)
    /// Preformatted text.
    case text(String)
    /// Not measured.
    case unavailable

    /// Display text.
    public var text: String {
        switch self {
        case let .rate(value): UIFormat.rate(value)
        case let .bytes(count): UIFormat.bytes(count)
        case let .age(since, now): UIFormat.ago(since, now: now)
        case let .text(text): text
        case .unavailable: MacStrings.unavailable
        }
    }
}

/// A labelled counter with monospaced digits and numeric text transitions.
public struct StatTile: View {
    private let title: String
    private let value: StatValue
    private let isStale: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Creates a tile; stale values are labelled and shown secondary.
    public init(title: String, value: StatValue, isStale: Bool = false) {
        self.title = title
        self.value = value
        self.isStale = isStale
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
            Text(title)
                .font(Typography.caption)
                .foregroundStyle(.secondary)
            Text(value.text)
                .font(Typography.counter)
                .monospacedDigit()
                .contentTransition(reduceMotion ? .opacity : .numericText())
                .foregroundStyle(isStale ? .secondary : .primary)
                .animation(.default, value: value)
            if isStale {
                Label(MacStrings.stale, systemImage: "clock.badge.questionmark")
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Self.accessibilityLabel(title: title, value: value, isStale: isStale))
        .accessibilityValue(value.text + (isStale ? MacStrings.staleQualifier : ""))
    }

    /// Spoken label: title, value and staleness.
    public static func accessibilityLabel(title: String, value: StatValue, isStale: Bool) -> String {
        MacStrings.statAnnouncement(String(title), String(value.text)) + (isStale ? MacStrings.staleQualifier : "")
    }
}
