// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore
import WGEXUI

/// Status components in every state: chips, stat tiles, sparkline, events,
/// captive window banner, profile rows and cards.
public struct StatusComponentsGallery: View {
    /// Creates the gallery.
    public init() {}

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            chips
            tiles
            Sparkline(title: "Download", series: PreviewFixtures.downloadSeries, now: PreviewFixtures.referenceDate)
                .frame(height: 48)
            EventsTimeline(events: PreviewFixtures.events, timeZone: .gmt, locale: Locale(identifier: "en_GB"))
            CaptiveWindowBanner(expires: PreviewFixtures.referenceDate.addingTimeInterval(272), now: PreviewFixtures.referenceDate) {}
            ForEach(PreviewFixtures.profileSummaries) { summary in
                ProfileRow(summary: summary)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), alignment: .top)], spacing: 16) {
                ForEach(PreviewFixtures.profileSummaries) { summary in
                    ProfileCard(summary: summary)
                }
            }
        }
    }

    private var chips: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), alignment: .leading)], alignment: .leading, spacing: 8) {
            ForEach(PreviewFixtures.presentations) { named in
                StateChip(presentation: named.presentation)
            }
        }
    }

    private var tiles: some View {
        let now = PreviewFixtures.referenceDate
        return Grid(horizontalSpacing: 16, verticalSpacing: 16) {
            GridRow {
                StatTile(title: "Download", value: .rate(1_250_000))
                StatTile(title: "Upload", value: .rate(84000))
                StatTile(title: "Last handshake", value: .age(since: now.addingTimeInterval(-18), now: now))
            }
            GridRow {
                StatTile(title: "Received", value: .bytes(4_200_000_000), isStale: true)
                StatTile(title: "Sent", value: .unavailable)
                StatTile(title: "Interface", value: .text("utun7"))
            }
        }
    }
}

#Preview("Status components, light") {
    ScrollView { StatusComponentsGallery().previewTraits(.light) }
}

#Preview("Status components, dark") {
    ScrollView { StatusComponentsGallery().previewTraits(.dark) }
}

#Preview("Status components, every variant") {
    PreviewTraitsMatrix { StatusComponentsGallery() }
}
