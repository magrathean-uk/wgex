// SPDX-License-Identifier: MIT

import Foundation

/// The WGEX design sheet (layout A, approved 21 Nov 2026): the named colours, shapes, spacing, type and parts of the Mac
/// window, and ``IOS`` for iPhone and iPad. `Resources/design-sheet.json` is the portable copy for other platforms;
/// `DesignSheetTests` keeps these constants equal to it, so the app never loads the JSON at run time.
public nonisolated enum DesignSheet {
    /// One named colour in light and dark appearance.
    public struct Pair: Sendable, Hashable {
        /// The colour in light appearance.
        public let light: ContrastColour
        /// The colour in dark appearance.
        public let dark: ContrastColour

        /// An opaque pair from 0xRRGGBB values.
        public init(_ light: UInt32, _ dark: UInt32) {
            self.light = ContrastColour(rgb: light)
            self.dark = ContrastColour(rgb: dark)
        }

        /// A pair with explicit colours.
        public init(light: ContrastColour, dark: ContrastColour) {
            self.light = light
            self.dark = dark
        }

        /// The colour for the appearance.
        public func value(dark isDark: Bool) -> ContrastColour {
            isDark ? dark : light
        }
    }

    /// The named colours, as in the sheet's `colours`.
    public enum Colours {
        public static let accent = Pair(0x1C5DBB, 0x62A3FF)
        public static let indigo = Pair(0x4B45C6, 0x918BFF)
        public static let success = Pair(0x086B33, 0x47E08C)
        public static let error = Pair(0xB81C17, 0xFF736B)
        public static let caution = Pair(0x8C5200, 0xFFB847)
        public static let pageBackground = Pair(0xF2F2F7, 0x0B0B0D)
        public static let sidebarBackground = Pair(0xE8E8EE, 0x151518)
        public static let card = Pair(0xFFFFFF, 0x1C1C1F)
        public static let text = Pair(0x1C1C1E, 0xF2F2F7)
        public static let textSecondary = Pair(0x636369, 0x98989F)
        /// Row dividers.
        public static let hairline = Pair(
            light: ContrastColour(rgb: 0x000000, opacity: 0.09),
            dark: ContrastColour(rgb: 0xFFFFFF, opacity: 0.1),
        )
        public static let cardBorder = Pair(
            light: ContrastColour(rgb: 0x000000, opacity: 0.18),
            dark: ContrastColour(rgb: 0xFFFFFF, opacity: 0.2),
        )
        /// Text on the solid (primary) button.
        public static let onAccent = Pair(0xFFFFFF, 0x06101F)

        /// Every named colour, keyed as in the JSON.
        public static let all: [String: Pair] = [
            "accent": accent, "indigo": indigo, "success": success, "error": error, "caution": caution,
            "pageBackground": pageBackground, "sidebarBackground": sidebarBackground, "card": card, "text": text,
            "textSecondary": textSecondary, "hairline": hairline, "cardBorder": cardBorder, "onAccent": onAccent,
        ]
    }

    /// Corner radii and stroke widths, in points.
    public enum Shape {
        public static let cardRadius = 10.0
        public static let controlRadius = 7.0
        public static let sidebarRowRadius = 6.0
        public static let cardBorderWidth = 0.5
        public static let buttonBorderWidth = 0.8
    }

    /// Spacing, in points.
    public enum Space {
        public static let scale = [4.0, 8.0, 12.0, 16.0, 20.0]
        public static let pagePadding = 16.0
        public static let groupGap = 10.0
        public static let rowPaddingVertical = 5.0
        public static let rowPaddingHorizontal = 12.0
    }

    /// Point sizes of the system font on the Mac.
    public enum TypeScale {
        public static let pageTitle = 17.0
        public static let body = 13.0
        public static let groupHeading = 11.0
        public static let sidebarHeading = 12.0
        public static let sidebarHeadingRuleWidth = 1.0
        public static let caption = 11.0
    }

    /// Opacities the parts apply to their colours.
    public enum Parts {
        public static let secondaryFillOpacity = 0.12
        public static let secondaryBorderOpacity = 0.3
        public static let sidebarStatusSize = 11.0
    }

    /// A system text style on iPhone and iPad; each follows Dynamic Type.
    public enum IOSTextRole: String, Sendable, CaseIterable {
        case title2, body, subheadline, footnote, caption
    }

    /// One iPhone and iPad text face: its role and weight (`regular`, `semibold` or `bold`).
    public struct IOSFace: Sendable, Hashable {
        public let role: IOSTextRole
        public let weight: String
    }

    /// iPhone and iPad (layout C, approved 21 Nov 2026): the colours, card, page padding, row padding and parts above at
    /// touch sizes, with Dynamic Type text roles in place of the Mac's point sizes. As in the sheet's `ios`.
    public enum IOS {
        /// Rows are at least a touch target tall.
        public static let rowMinHeight = 44.0
        /// Above and below a row's content: a 36 pt field box fills a 44 pt row.
        public static let rowPaddingVertical = 4.0
        public static let groupGap = 12.0
        /// Primary and secondary buttons.
        public static let buttonRadius = 8.0
        public static let body = IOSFace(role: .body, weight: "regular")
        /// "Tunnels" and "Settings" on the first screen, in the text colour over a rule.
        public static let firstScreenHeading = IOSFace(role: .subheadline, weight: "bold")
        public static let firstScreenHeadingRuleWidth = 1.0
        /// Group headings on every other page, in textSecondary.
        public static let groupHeading = IOSFace(role: .footnote, weight: "semibold")
        /// Group footers and notes, in textSecondary.
        public static let caption = IOSFace(role: .footnote, weight: "regular")
        /// Compact button titles.
        public static let button = IOSFace(role: .subheadline, weight: "semibold")
        /// Labels and field text of a form on the grid, in the text colour.
        public static let field = IOSFace(role: .subheadline, weight: "regular")
        /// Keys and addresses, set monospaced one step under the field text.
        public static let key = IOSFace(role: .footnote, weight: "regular")
        /// A sheet's title under its toolbar, in the text colour.
        public static let sheetTitle = IOSFace(role: .title2, weight: "bold")
    }

    /// The form grid (approved 21 Nov 2026), in points at the default text size: every card of a form shares one
    /// label column and one field column, so fields start and end on the same two lines. As in the sheet's `ios.grid`.
    public enum IOSGrid {
        /// Page margin around the cards.
        public static let screenMargin = 16.0
        /// Inside a card, left and right.
        public static let cardPadding = 12.0
        /// Every spacing is a multiple of this step.
        public static let step = 4.0
        public static let labelColumn = 112.0
        /// Between the label column and the field column.
        public static let columnGap = 8.0
        public static let rowMinHeight = 44.0
        public static let fieldHeight = 36.0
        public static let fieldRadius = 8.0
        /// Text inset inside a field box, and of a read-only value in the field column.
        public static let fieldInset = 10.0
        /// A compact button's visible height; its hit area stays a touch target.
        public static let buttonHeight = 32.0
        /// A compact button's side padding.
        public static let buttonPadding = 12.0
        /// Between the buttons of an action row.
        public static let buttonGap = 8.0
        /// An icon button's side.
        public static let iconButton = 32.0
        /// The widest a form's cards grow (iPad); the form is centred.
        public static let formMaxWidth = 560.0
        /// The side of an inline glyph button in a field box (an address's remove glyph).
        public static let glyph = 20.0
        /// From a card's bottom edge to the next group heading.
        public static let headingAbove = 12.0
        /// From a group heading to its card.
        public static let headingBelow = 4.0
        /// How far the system switch draws past its frame on the trailing side; a switch row pulls it in by this much,
        /// so the track ends on the field column's right line.
        public static let switchOverhang = 2.0
        /// How far a pop-up picker's chevron stops short of its frame on the trailing side; a picker row lets it out by
        /// this much, so the chevron ends on the field column's right line.
        public static let menuInset = 2.0
        /// The system toolbar's side inset on iPad; the sheet's toolbar buttons add the rest of the screen margin.
        public static let padBarInset = 10.0
    }
}

public extension ContrastColour {
    /// A colour from a 0xRRGGBB value.
    nonisolated init(rgb: UInt32, opacity: Double = 1) {
        self.init(
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255,
            opacity: opacity,
        )
    }
}
