// SPDX-License-Identifier: MIT

import SwiftUI

/// A plain tinted evidence label; presentations distinguish received and never-reported status.
public struct StateChip: View {
    private let title: String
    private let glyph: String
    private let colour: StateColor
    @Environment(\.colorScheme) private var scheme

    /// Creates a chip from parts.
    public init(title: String, glyph: String, colour: StateColor) {
        self.title = title
        self.glyph = glyph
        self.colour = colour
    }

    /// Creates a chip for a presentation.
    public init(presentation: ProtectionPresentation) {
        self.init(title: presentation.provenanceTitle, glyph: presentation.glyph, colour: presentation.colour)
    }

    /// The view body.
    public var body: some View {
        Label {
            Text(title)
        } icon: {
            Image(systemName: glyph)
        }
        .font(Typography.chip)
        .foregroundStyle(colour.labelColor(for: scheme))
        .padding(.horizontal, Spacing.medium)
        .padding(.vertical, Spacing.extraSmall)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Self.accessibilityLabel(title: title))
    }

    /// Spoken label.
    public static func accessibilityLabel(title: String) -> String {
        MacStrings.protectionAnnouncementLabel(String(title))
    }
}

/// A small coloured dot that always travels with a text label.
public struct StateDot: View {
    private let colour: StateColor

    /// Creates a dot.
    public init(colour: StateColor) {
        self.colour = colour
    }

    /// The view body.
    public var body: some View {
        Circle()
            .fill(colour.color)
            .frame(width: Spacing.small + Spacing.extraSmall / 2, height: Spacing.small + Spacing.extraSmall / 2)
            .accessibilityHidden(true)
    }
}
