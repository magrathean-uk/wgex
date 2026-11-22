// SPDX-License-Identifier: MIT

import Foundation

/// iOS numeric scales, kept independent of UIKit for host verification. The layout C entries (page, groupGap, row
/// padding, button radius, strokes, touch height) come from ``DesignSheet``; the older mac-v2 steps stay for the screens
/// that still use them. Native iOS fonts use text roles; controls and rows have a 44 pt minimum.
public nonisolated enum IOSDesignScale {
    public enum Space {
        public static let micro: CGFloat = 2
        public static let small: CGFloat = 6
        public static let medium: CGFloat = 10
        public static let section: CGFloat = 14
        public static let inset: CGFloat = 16
        public static let large: CGFloat = 20
        public static let detail: CGFloat = 24
        public static let settings: CGFloat = 36
        /// Page margins around the cards.
        public static let page = CGFloat(DesignSheet.Space.pagePadding)
        /// Between one group (heading, card, footer) and the next.
        public static let groupGap = CGFloat(DesignSheet.IOS.groupGap)
        /// Inside a card row, left and right.
        public static let rowHorizontal = CGFloat(DesignSheet.Space.rowPaddingHorizontal)
        /// Inside a card row, above and below; the row's minimum height usually decides.
        public static let rowVertical = CGFloat(DesignSheet.IOS.rowPaddingVertical)
    }

    public enum Radius {
        public static let control: CGFloat = 7
        public static let group: CGFloat = 8
        public static let card = CGFloat(DesignSheet.Shape.cardRadius)
        public static let popover: CGFloat = 12
        public static let window: CGFloat = 14
        /// Primary and secondary buttons.
        public static let button = CGFloat(DesignSheet.IOS.buttonRadius)
    }

    public enum Stroke {
        /// The card border.
        public static let card = CGFloat(DesignSheet.Shape.cardBorderWidth)
        /// The secondary button border.
        public static let button = CGFloat(DesignSheet.Shape.buttonBorderWidth)
        /// Row dividers inside a card.
        public static let hairline: CGFloat = 0.5
        /// The rule under a first-screen heading.
        public static let headingRule = CGFloat(DesignSheet.IOS.firstScreenHeadingRuleWidth)
    }

    public enum TypeSize {
        public static let caption: CGFloat = 11
        public static let note: CGFloat = 11.5
        public static let small: CGFloat = 12
        public static let body: CGFloat = 13
        public static let status: CGFloat = 14
        public static let heading: CGFloat = 15
        public static let title: CGFloat = 20
        public static let welcome: CGFloat = 24
    }

    /// The form grid from ``DesignSheet/IOSGrid`` at the default text size; the row parts scale the column, field and
    /// button sizes with Dynamic Type.
    public enum Grid {
        public static let screenMargin = CGFloat(DesignSheet.IOSGrid.screenMargin)
        public static let cardPadding = CGFloat(DesignSheet.IOSGrid.cardPadding)
        public static let step = CGFloat(DesignSheet.IOSGrid.step)
        public static let labelColumn = CGFloat(DesignSheet.IOSGrid.labelColumn)
        public static let columnGap = CGFloat(DesignSheet.IOSGrid.columnGap)
        public static let rowMinHeight = CGFloat(DesignSheet.IOSGrid.rowMinHeight)
        public static let fieldHeight = CGFloat(DesignSheet.IOSGrid.fieldHeight)
        public static let fieldRadius = CGFloat(DesignSheet.IOSGrid.fieldRadius)
        public static let fieldInset = CGFloat(DesignSheet.IOSGrid.fieldInset)
        public static let buttonHeight = CGFloat(DesignSheet.IOSGrid.buttonHeight)
        public static let buttonPadding = CGFloat(DesignSheet.IOSGrid.buttonPadding)
        public static let buttonGap = CGFloat(DesignSheet.IOSGrid.buttonGap)
        public static let iconButton = CGFloat(DesignSheet.IOSGrid.iconButton)
        public static let formMaxWidth = CGFloat(DesignSheet.IOSGrid.formMaxWidth)
        public static let glyph = CGFloat(DesignSheet.IOSGrid.glyph)
        public static let headingAbove = CGFloat(DesignSheet.IOSGrid.headingAbove)
        public static let headingBelow = CGFloat(DesignSheet.IOSGrid.headingBelow)
        public static let switchOverhang = CGFloat(DesignSheet.IOSGrid.switchOverhang)
        public static let menuInset = CGFloat(DesignSheet.IOSGrid.menuInset)
        public static let padBarInset = CGFloat(DesignSheet.IOSGrid.padBarInset)
    }

    /// iOS touch target and the minimum height of a card row.
    public static let minimumTouchHeight = CGFloat(DesignSheet.IOS.rowMinHeight)
}
