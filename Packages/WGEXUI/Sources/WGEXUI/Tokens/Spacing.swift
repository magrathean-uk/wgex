// SPDX-License-Identifier: MIT

import SwiftUI

/// Spacing on a 4-point grid (plan 06 §2).
public nonisolated enum Spacing {
    /// The grid unit.
    public static let unit: CGFloat = 4
    /// 4 pt.
    public static let extraSmall: CGFloat = unit
    /// 8 pt.
    public static let small: CGFloat = unit * 2
    /// 12 pt.
    public static let medium: CGFloat = unit * 3
    /// 16 pt.
    public static let large: CGFloat = unit * 4
    /// 20 pt; padding inside glass containers.
    public static let glassPadding: CGFloat = unit * 5
    /// 24 pt.
    public static let extraLarge: CGFloat = unit * 6
    /// 32 pt; between sections.
    public static let section: CGFloat = unit * 8

    /// `count` grid units.
    public static func grid(_ count: Int) -> CGFloat {
        unit * CGFloat(count)
    }
}

/// Corner radii. Content nested in a card uses `.containerRelative` so it
/// follows the card's shape; cards declare that shape with ``cardShape``.
public nonisolated enum Radius {
    /// Corner radius of an opaque content card.
    public static let card: CGFloat = Spacing.glassPadding

    /// Shape of an opaque content card.
    public static var cardShape: RoundedRectangle {
        RoundedRectangle(cornerRadius: card, style: .continuous)
    }
}

public extension View {
    /// Opaque grouped content background with a card shape that nested
    /// `.containerRelative` shapes follow. Content groups stay opaque; glass
    /// is reserved for system chrome and the orb.
    func cardBackground() -> some View {
        padding(Spacing.glassPadding)
            .background(.background.secondary, in: Radius.cardShape)
            .containerShape(Radius.cardShape)
    }
}
