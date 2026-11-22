// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// The last 32 tunnel events, newest first.
public struct EventsTimeline: View {
    private let events: [TunnelEvent]
    private let timeZone: TimeZone
    private let locale: Locale

    /// Creates a timeline; `events` are oldest first, as in ``WGEXCore/TunnelStatus``.
    public init(events: [TunnelEvent], timeZone: TimeZone = .current, locale: Locale = .current) {
        self.events = events
        self.timeZone = timeZone
        self.locale = locale
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.small) {
            Text(MacStrings.events)
                .font(Typography.cardTitle)
            let rows = EventDescription.timeline(events)
            if rows.isEmpty {
                Text(MacStrings.noEventsYet)
                    .font(Typography.body)
                    .foregroundStyle(.secondary)
            }
            ForEach(Array(rows.enumerated()), id: \.offset) { _, event in
                row(event)
            }
        }
        .accessibilityIdentifier("wgex.events.timeline")
    }

    private func row(_ event: TunnelEvent) -> some View {
        let description = EventDescription.describe(event.kind)
        return HStack(alignment: .firstTextBaseline, spacing: Spacing.small) {
            Text(Self.timeText(event.date, timeZone: timeZone, locale: locale))
                .font(Typography.timestamp)
                .foregroundStyle(.secondary)
            Image(systemName: description.glyph)
                .foregroundStyle(.secondary)
            Text(description.text)
                .font(Typography.body)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Self.accessibilityLabel(for: event, timeZone: timeZone, locale: locale))
        .wgexAX(
            .events,
            "timelineEvent",
            label: Self.accessibilityLabel(for: event, timeZone: timeZone, locale: locale),
            item: String(event.date.timeIntervalSince1970),
        )
    }

    /// "14:02".
    public static func timeText(_ date: Date, timeZone: TimeZone, locale: Locale) -> String {
        var style = Date.FormatStyle(date: .omitted, time: .shortened, locale: locale)
        style.timeZone = timeZone
        return date.formatted(style)
    }

    /// "14:02, Network changed, reconnecting".
    public static func accessibilityLabel(for event: TunnelEvent, timeZone: TimeZone, locale: Locale) -> String {
        MacStrings.eventAnnouncement(
            String(timeText(event.date, timeZone: timeZone, locale: locale)),
            String(EventDescription.describe(event.kind).text),
        )
    }
}
