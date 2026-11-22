// SPDX-License-Identifier: MIT

import Foundation
import SwiftUI
import Testing
import WGEXUI

private struct SheetFile: Decodable {
    struct Value: Decodable {
        let hex: String
        let opacity: Double
    }

    struct Pair: Decodable {
        let light: Value
        let dark: Value
    }

    struct Shape: Decodable {
        let cardRadius, controlRadius, sidebarRowRadius, cardBorderWidth, buttonBorderWidth: Double
    }

    struct Space: Decodable {
        let scale: [Double]
        let pagePadding, groupGap, rowPaddingVertical, rowPaddingHorizontal: Double
    }

    struct Face: Decodable {
        let size: Double
        let weight: String
        let ruleWidth: Double?
    }

    struct TypeScale: Decodable {
        let pageTitle, body, groupHeading, sidebarHeading, caption: Face
        let monospacedDigits: Bool
    }

    struct Part: Decodable {
        let fillOpacity: Double?
        let borderOpacity: Double?
        let selectedText: String?
        let unselectedText: String?
        let size: Double?
    }

    struct IOSFace: Decodable {
        let role: String
        let weight: String
        let colour: String?
        let ruleWidth: Double?
        let monospaced: Bool?
    }

    struct IOSType: Decodable {
        let body, firstScreenHeading, groupHeading, caption, button, field, key, sheetTitle: IOSFace
    }

    struct Grid: Decodable {
        let screenMargin, cardPadding, step, labelColumn, columnGap, rowMinHeight: Double
        let fieldHeight, fieldRadius, fieldInset, buttonHeight, buttonPadding, buttonGap, iconButton, formMaxWidth: Double
        let glyph, headingAbove, headingBelow, switchOverhang, menuInset, padBarInset: Double
    }

    struct IOS: Decodable {
        let rowMinHeight, rowPaddingVertical, groupGap, buttonRadius: Double
        let type: IOSType
        let grid: Grid
    }

    let colours: [String: Pair]
    let shape: Shape
    let spacing: Space
    let type: TypeScale
    let parts: [String: Part]
    let ios: IOS
}

/// The Swift constants equal the portable `design-sheet.json`, and the sheet's text colours stay readable.
private struct DesignSheetTests {
    private func sheet() throws -> SheetFile {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appending(path: "Sources/WGEXUI/Resources/design-sheet.json"))
        return try JSONDecoder().decode(SheetFile.self, from: data)
    }

    private func text(_ value: SheetFile.Value) -> String {
        value.opacity < 1 ? "\(value.hex) @\(String(format: "%.2f", value.opacity))" : value.hex
    }

    @Test func `every colour in the JSON equals the Swift constant and no name is missing`() throws {
        let file = try sheet()
        #expect(Set(file.colours.keys) == Set(DesignSheet.Colours.all.keys))
        for (name, pair) in file.colours {
            let swift = try #require(DesignSheet.Colours.all[name])
            #expect(swift.light.hex == text(pair.light), "\(name) light")
            #expect(swift.dark.hex == text(pair.dark), "\(name) dark")
        }
    }

    @Test func `shape, spacing, type and part values equal the Swift constants`() throws {
        let file = try sheet()
        #expect(file.shape.cardRadius == DesignSheet.Shape.cardRadius)
        #expect(file.shape.controlRadius == DesignSheet.Shape.controlRadius)
        #expect(file.shape.sidebarRowRadius == DesignSheet.Shape.sidebarRowRadius)
        #expect(file.shape.cardBorderWidth == DesignSheet.Shape.cardBorderWidth)
        #expect(file.shape.buttonBorderWidth == DesignSheet.Shape.buttonBorderWidth)
        #expect(file.spacing.scale == DesignSheet.Space.scale)
        #expect(file.spacing.pagePadding == DesignSheet.Space.pagePadding)
        #expect(file.spacing.groupGap == DesignSheet.Space.groupGap)
        #expect(file.spacing.rowPaddingVertical == DesignSheet.Space.rowPaddingVertical)
        #expect(file.spacing.rowPaddingHorizontal == DesignSheet.Space.rowPaddingHorizontal)
        #expect(file.type.pageTitle.size == DesignSheet.TypeScale.pageTitle && file.type.pageTitle.weight == "bold")
        #expect(file.type.body.size == DesignSheet.TypeScale.body)
        #expect(file.type.groupHeading.size == DesignSheet.TypeScale.groupHeading && file.type.groupHeading.weight == "semibold")
        #expect(file.type.sidebarHeading.size == DesignSheet.TypeScale.sidebarHeading && file.type.sidebarHeading.weight == "bold")
        #expect(file.type.sidebarHeading.ruleWidth == DesignSheet.TypeScale.sidebarHeadingRuleWidth)
        #expect(file.type.caption.size == DesignSheet.TypeScale.caption)
        #expect(file.type.monospacedDigits)
        #expect(file.parts["secondaryButton"]?.fillOpacity == DesignSheet.Parts.secondaryFillOpacity)
        #expect(file.parts["secondaryButton"]?.borderOpacity == DesignSheet.Parts.secondaryBorderOpacity)
        #expect(file.parts["sidebarSelection"]?.unselectedText == "text" && file.parts["sidebarSelection"]?.selectedText == "onHighlight")
        #expect(file.parts["sidebarStatus"]?.size == DesignSheet.Parts.sidebarStatusSize)
    }

    @Test func `iOS sizes and text roles equal the Swift constants`() throws {
        let ios = try sheet().ios
        let swift = DesignSheet.IOS.self
        #expect(ios.rowMinHeight == swift.rowMinHeight)
        #expect(ios.rowPaddingVertical == swift.rowPaddingVertical)
        #expect(ios.groupGap == swift.groupGap)
        #expect(ios.buttonRadius == swift.buttonRadius)
        let faces: [(String, SheetFile.IOSFace, DesignSheet.IOSFace)] = [
            ("body", ios.type.body, swift.body),
            ("firstScreenHeading", ios.type.firstScreenHeading, swift.firstScreenHeading),
            ("groupHeading", ios.type.groupHeading, swift.groupHeading),
            ("caption", ios.type.caption, swift.caption),
            ("button", ios.type.button, swift.button),
            ("field", ios.type.field, swift.field),
            ("key", ios.type.key, swift.key),
            ("sheetTitle", ios.type.sheetTitle, swift.sheetTitle),
        ]
        for (name, file, face) in faces {
            #expect(file.role == face.role.rawValue && file.weight == face.weight, "\(name)")
        }
        #expect(ios.type.firstScreenHeading.ruleWidth == swift.firstScreenHeadingRuleWidth)
        #expect(ios.type.firstScreenHeading.colour == "text" && ios.type.firstScreenHeading.weight == "bold")
        #expect(ios.type.groupHeading.colour == "textSecondary" && ios.type.groupHeading.weight == "semibold")
        #expect(ios.rowMinHeight >= 44, "rows stay a touch target tall")
        #expect(ios.type.key.monospaced == true)
    }

    /// The form grid: every number equals the Swift constant, spacing is in steps of 4, the field box fills the row
    /// between the row padding, and a compact button with its touch extension still reaches a touch target.
    @Test func `iOS grid values equal the Swift constants`() throws {
        let file = try sheet().ios.grid
        typealias Grid = DesignSheet.IOSGrid
        let pairs: [(String, Double, Double)] = [
            ("screenMargin", file.screenMargin, Grid.screenMargin), ("cardPadding", file.cardPadding, Grid.cardPadding),
            ("step", file.step, Grid.step), ("labelColumn", file.labelColumn, Grid.labelColumn),
            ("columnGap", file.columnGap, Grid.columnGap), ("rowMinHeight", file.rowMinHeight, Grid.rowMinHeight),
            ("fieldHeight", file.fieldHeight, Grid.fieldHeight), ("fieldRadius", file.fieldRadius, Grid.fieldRadius),
            ("fieldInset", file.fieldInset, Grid.fieldInset), ("buttonHeight", file.buttonHeight, Grid.buttonHeight),
            ("buttonPadding", file.buttonPadding, Grid.buttonPadding), ("buttonGap", file.buttonGap, Grid.buttonGap),
            ("iconButton", file.iconButton, Grid.iconButton), ("formMaxWidth", file.formMaxWidth, Grid.formMaxWidth),
            ("glyph", file.glyph, Grid.glyph), ("headingAbove", file.headingAbove, Grid.headingAbove),
            ("headingBelow", file.headingBelow, Grid.headingBelow), ("switchOverhang", file.switchOverhang, Grid.switchOverhang),
            ("menuInset", file.menuInset, Grid.menuInset), ("padBarInset", file.padBarInset, Grid.padBarInset),
        ]
        for (name, json, swift) in pairs {
            #expect(json == swift, "\(name)")
        }
        for spacing in [
            Grid.screenMargin, Grid.cardPadding, Grid.columnGap, Grid.buttonPadding, Grid.buttonGap, Grid.fieldHeight, Grid.glyph,
            Grid.headingAbove, Grid.headingBelow,
        ] {
            #expect(spacing.truncatingRemainder(dividingBy: Grid.step) == 0, "\(spacing) is a step of 4")
        }
        #expect(Grid.screenMargin == DesignSheet.Space.pagePadding && Grid.cardPadding == DesignSheet.Space.rowPaddingHorizontal)
        #expect(Grid.rowMinHeight == DesignSheet.IOS.rowMinHeight)
        #expect(Grid.fieldHeight + 2 * DesignSheet.IOS.rowPaddingVertical == Grid.rowMinHeight)
        #expect(Grid.buttonHeight < Grid.rowMinHeight && Grid.iconButton == Grid.buttonHeight)
        // System-control corrections stay small, and the iPad toolbar reaches the screen margin.
        #expect(Grid.switchOverhang < Grid.step && Grid.menuInset < Grid.step && Grid.padBarInset < Grid.screenMargin)
    }

    /// Text colours on the card and page backgrounds, and onAccent on both ends of the primary gradient, meet 4.5:1.
    @Test(arguments: [false, true])
    func `sheet text colours meet body text contrast`(_ dark: Bool) {
        let colours = DesignSheet.Colours.self
        let grounds = [colours.card, colours.pageBackground].map { $0.value(dark: dark) }
        let texts = [
            "text": colours.text,
            "textSecondary": colours.textSecondary,
            "accent": colours.accent,
            "success": colours.success,
            "error": colours.error,
            "caution": colours.caution,
        ]
        for ground in grounds {
            for (name, pair) in texts {
                let ratio = ContrastColour.ratio(pair.value(dark: dark), ground)
                #expect(ratio >= 4.5, "\(name) on \(ground.hex), dark \(dark): \(ratio)")
            }
        }
        // The sidebar shows text, accent and the textSecondary status word on sidebarBackground.
        let sidebar = colours.sidebarBackground.value(dark: dark)
        for pair in [colours.text, colours.accent] {
            #expect(ContrastColour.ratio(pair.value(dark: dark), sidebar) >= 4.5)
        }
        #expect(ContrastColour.ratio(colours.textSecondary.value(dark: dark), sidebar) >= 4.5)
        for end in [colours.accent, colours.indigo] {
            let ratio = ContrastColour.ratio(colours.onAccent.value(dark: dark), end.value(dark: dark))
            #expect(ratio >= 4.5, "onAccent on \(end.value(dark: dark).hex): \(ratio)")
        }
        // The secondary button's accent title sits on accent at 12% over the card or the page.
        for ground in grounds {
            var tint = colours.accent.value(dark: dark)
            tint.opacity = DesignSheet.Parts.secondaryFillOpacity
            let fill = tint.composited(over: ground)
            let ratio = ContrastColour.ratio(colours.accent.value(dark: dark), fill)
            #expect(ratio >= 4.5, "accent on the secondary fill over \(ground.hex): \(ratio)")
        }
    }

    #if os(macOS)
        @Test(arguments: [false, true])
        func `Mac colours follow the appearance`(_ dark: Bool) {
            var environment = EnvironmentValues()
            environment.colorScheme = dark ? .dark : .light
            let resolved = MacDesign.accent.resolve(in: environment)
            let colour = ContrastColour(red: Double(resolved.red), green: Double(resolved.green), blue: Double(resolved.blue))
            #expect(colour.hex == DesignSheet.Colours.accent.value(dark: dark).hex)
        }
    #endif
}
