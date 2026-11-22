// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXUI

private struct IOSDesignTests {
    @Test func `numeric scales retain the canonical mac v2 values`() {
        #expect([
            IOSDesignScale.Space.micro,
            IOSDesignScale.Space.small,
            IOSDesignScale.Space.medium,
            IOSDesignScale.Space.section,
            IOSDesignScale.Space.inset,
            IOSDesignScale.Space.large,
            IOSDesignScale.Space.detail,
            IOSDesignScale.Space.settings,
        ] == [2, 6, 10, 14, 16, 20, 24, 36])
        #expect([
            IOSDesignScale.Radius.control,
            IOSDesignScale.Radius.group,
            IOSDesignScale.Radius.card,
            IOSDesignScale.Radius.popover,
            IOSDesignScale.Radius.window,
        ] == [7, 8, 10, 12, 14])
        #expect([
            IOSDesignScale.TypeSize.caption,
            IOSDesignScale.TypeSize.note,
            IOSDesignScale.TypeSize.small,
            IOSDesignScale.TypeSize.body,
            IOSDesignScale.TypeSize.status,
            IOSDesignScale.TypeSize.heading,
            IOSDesignScale.TypeSize.title,
            IOSDesignScale.TypeSize.welcome,
        ] == [11, 11.5, 12, 13, 14, 15, 20, 24])
        #expect(IOSDesignScale.minimumTouchHeight == 44)
    }

    /// Layout C: 16 pt page margins, 12 pt between groups, rows 44 pt tall with 12 pt side padding, radius 10 cards with a
    /// 0.5 pt border, radius 8 buttons with a 0.8 pt border, a 1 pt rule under first-screen headings.
    @Test func `layout C sizes come from the design sheet`() {
        #expect(IOSDesignScale.Space.page == 16 && IOSDesignScale.Space.page == CGFloat(DesignSheet.Space.pagePadding))
        #expect(IOSDesignScale.Space.groupGap == 12 && IOSDesignScale.Space.groupGap == CGFloat(DesignSheet.IOS.groupGap))
        #expect(IOSDesignScale.Space.rowHorizontal == 12)
        #expect(IOSDesignScale.Space.rowVertical == CGFloat(DesignSheet.IOS.rowPaddingVertical))
        #expect(IOSDesignScale.Radius.card == CGFloat(DesignSheet.Shape.cardRadius))
        #expect(IOSDesignScale.Radius.button == 8 && IOSDesignScale.Radius.button == CGFloat(DesignSheet.IOS.buttonRadius))
        #expect(IOSDesignScale.Stroke.card == 0.5 && IOSDesignScale.Stroke.button == 0.8)
        #expect(IOSDesignScale.Stroke.headingRule == 1)
        #expect(IOSDesignScale.minimumTouchHeight == CGFloat(DesignSheet.IOS.rowMinHeight))
    }

    @Test func `text roles keep Dynamic Type and the sheet weights`() {
        #expect(DesignSheet.IOS.body.role == .body)
        #expect(DesignSheet.IOS.firstScreenHeading.role == .subheadline && DesignSheet.IOS.firstScreenHeading.weight == "bold")
        #expect(DesignSheet.IOS.groupHeading.role == .footnote && DesignSheet.IOS.groupHeading.weight == "semibold")
        #expect(DesignSheet.IOS.caption.role == .footnote)
        #expect(DesignSheet.IOS.button.role == .subheadline && DesignSheet.IOS.button.weight == "semibold")
        #expect(DesignSheet.IOS.field.role == .subheadline && DesignSheet.IOS.key.role == .footnote)
        #expect(DesignSheet.IOS.sheetTitle.role == .title2 && DesignSheet.IOS.sheetTitle.weight == "bold")
    }

    /// The form grid reaches the views through IOSDesignScale unchanged.
    @Test func `grid sizes come from the design sheet`() {
        typealias Grid = IOSDesignScale.Grid
        #expect(Grid.labelColumn == 112 && Grid.columnGap == 8 && Grid.fieldHeight == 36 && Grid.fieldInset == 10)
        #expect(Grid.buttonHeight == 32 && Grid.buttonPadding == 12 && Grid.buttonGap == 8 && Grid.iconButton == 32)
        #expect(Grid.fieldRadius == 8 && Grid.formMaxWidth == 560 && Grid.step == 4)
        #expect(Grid.screenMargin == IOSDesignScale.Space.page && Grid.cardPadding == IOSDesignScale.Space.rowHorizontal)
        #expect(Grid.labelColumn == CGFloat(DesignSheet.IOSGrid.labelColumn))
        #expect(Grid.glyph == 20 && Grid.headingAbove == 12 && Grid.headingBelow == 4)
        #expect(Grid.switchOverhang == 2 && Grid.menuInset == 2 && Grid.padBarInset == 10)
        #expect(IOSDesignScale.Space.rowVertical == 4)
    }
}
