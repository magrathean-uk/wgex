// SPDX-License-Identifier: MIT

// No platform guard: the Mac and the iPhone and iPad Log pages list the same event lines (SPEC 8.4, 10).
import Foundation
import WGEXCore

/// The Log page's Events lines: time, category and plain sentence, oldest first.
package nonisolated enum TunnelEventLines {
    /// One Events line.
    package nonisolated struct Line: Equatable, Identifiable, Sendable {
        package let id: Int
        package let date: Date
        package let category: String
        package let sentence: String
    }

    /// The Events tab's category for an event (SPEC 8.4).
    package static func category(_ kind: TunnelEvent.Kind) -> String {
        switch kind {
        case .phaseChanged, .failed: MacStrings.categoryTunnel
        case .handshakeCompleted, .txWithoutRx, .endpointChanged: MacStrings.categoryServer
        case .protectionChanged: MacStrings.categoryProtection
        case .transportChanged, .pathChanged: MacStrings.categoryNetwork
        }
    }

    /// Every held event, oldest first (the newest at the bottom), at most the backend's 32.
    package static func lines(_ events: [TunnelEvent]) -> [Line] {
        events.suffix(TunnelStatus.recentEventLimit).enumerated().map { index, event in
            Line(id: index, date: event.date, category: category(event.kind), sentence: EventDescription.describe(event.kind).text)
        }
    }

    /// The Events tab as saved: one line each, GMT timestamp, category and sentence.
    package static func text(_ lines: [Line]) -> String {
        lines.map { "\($0.date.formatted(timestamp)) \($0.category) \($0.sentence)\n" }.joined()
    }

    private static let timestamp = Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt)
}
