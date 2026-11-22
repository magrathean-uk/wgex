// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI

    /// The Mac window's tokens, taken from ``DesignSheet`` (layout A). Each colour follows the system appearance, light or
    /// dark, through a dynamic `NSColor`.
    public enum MacDesign {
        // MARK: Sheet colours

        public nonisolated static let accent = Color(sheet: DesignSheet.Colours.accent)
        public nonisolated static let indigo = Color(sheet: DesignSheet.Colours.indigo)
        public nonisolated static let success = Color(sheet: DesignSheet.Colours.success)
        public nonisolated static let error = Color(sheet: DesignSheet.Colours.error)
        public nonisolated static let caution = Color(sheet: DesignSheet.Colours.caution)
        public nonisolated static let pageBackground = Color(sheet: DesignSheet.Colours.pageBackground)
        public nonisolated static let sidebarBackground = Color(sheet: DesignSheet.Colours.sidebarBackground)
        public nonisolated static let card = Color(sheet: DesignSheet.Colours.card)
        public nonisolated static let text = Color(sheet: DesignSheet.Colours.text)
        public nonisolated static let textSecondary = Color(sheet: DesignSheet.Colours.textSecondary)
        /// Row dividers inside a card.
        public nonisolated static let hairline = Color(sheet: DesignSheet.Colours.hairline)
        public nonisolated static let cardBorder = Color(sheet: DesignSheet.Colours.cardBorder)
        /// Text on the primary button's gradient.
        public nonisolated static let onAccent = Color(sheet: DesignSheet.Colours.onAccent)

        // MARK: Names the screens already use

        public nonisolated static let label = text
        /// Secondary text: row values, notes and captions.
        public nonisolated static let label2 = textSecondary
        /// Chevrons and other quiet glyphs.
        public nonisolated static let label3 = textSecondary.opacity(0.7)
        public nonisolated static let separator = hairline
        public nonisolated static let window = pageBackground
        public nonisolated static let pane = pageBackground
        public nonisolated static let red = error

        public enum Space {
            public static let page = CGFloat(DesignSheet.Space.pagePadding)
            public static let groupGap = CGFloat(DesignSheet.Space.groupGap)
            public static let rowVertical = CGFloat(DesignSheet.Space.rowPaddingVertical)
            public static let rowHorizontal = CGFloat(DesignSheet.Space.rowPaddingHorizontal)
            public static let section: CGFloat = 14
        }

        public enum Radius {
            public static let control = CGFloat(DesignSheet.Shape.controlRadius)
            public static let card = CGFloat(DesignSheet.Shape.cardRadius)
            public static let sidebarRow = CGFloat(DesignSheet.Shape.sidebarRowRadius)
        }

        public enum Stroke {
            public static let card = CGFloat(DesignSheet.Shape.cardBorderWidth)
            public static let button = CGFloat(DesignSheet.Shape.buttonBorderWidth)
            public static let sidebarHeadingRule = CGFloat(DesignSheet.TypeScale.sidebarHeadingRuleWidth)
        }

        // MARK: Type

        public static let pageTitle: Font = .system(size: DesignSheet.TypeScale.pageTitle, weight: .bold)
        public static let groupHeading: Font = .system(size: DesignSheet.TypeScale.groupHeading, weight: .semibold)
        public static let sidebarHeading: Font = .system(size: DesignSheet.TypeScale.sidebarHeading, weight: .bold)
        public static let sidebarStatus: Font = .system(size: DesignSheet.Parts.sidebarStatusSize)
        public static let button: Font = .system(size: DesignSheet.TypeScale.body, weight: .semibold)
        public static let caption: Font = .system(size: DesignSheet.TypeScale.caption)
        public static let note: Font = .system(size: DesignSheet.TypeScale.caption)
        public static let small: Font = .system(size: DesignSheet.TypeScale.caption + 1)
        public static let body: Font = .system(size: DesignSheet.TypeScale.body)
        public static let heading: Font = .system(size: DesignSheet.TypeScale.pageTitle - 2, weight: .bold)
    }

    public extension Color {
        /// A colour that resolves to the pair's light or dark value with the appearance.
        nonisolated init(sheet pair: DesignSheet.Pair) {
            self.init(nsColor: NSColor(name: nil) { appearance in
                let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
                let colour = pair.value(dark: isDark)
                return NSColor(
                    srgbRed: colour.red, green: colour.green, blue: colour.blue, alpha: colour.opacity,
                )
            })
        }
    }

    package extension View {
        /// The sheet's card: card fill, a 0.5 pt card border and radius 10.
        func macCard(padding: CGFloat = MacDesign.Space.section) -> some View {
            self.padding(padding)
                .background(MacDesign.card, in: .rect(cornerRadius: MacDesign.Radius.card))
                .overlay {
                    RoundedRectangle(cornerRadius: MacDesign.Radius.card)
                        .strokeBorder(MacDesign.cardBorder, lineWidth: MacDesign.Stroke.card)
                }
        }
    }
#endif
