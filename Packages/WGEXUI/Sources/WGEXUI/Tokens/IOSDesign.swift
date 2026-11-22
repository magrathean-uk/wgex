// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import UIKit

    /// The iPhone and iPad tokens (layout C), taken from ``DesignSheet``. Each colour follows the system appearance, light
    /// or dark, through a dynamic `UIColor`; text uses Dynamic Type roles. The names the screens already use point at the
    /// sheet where it has a value.
    public enum IOSDesign {
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
        /// The card border and the rule under a first-screen heading.
        public nonisolated static let cardBorder = Color(sheet: DesignSheet.Colours.cardBorder)
        /// Text on the primary button's gradient.
        public nonisolated static let onAccent = Color(sheet: DesignSheet.Colours.onAccent)

        // MARK: Names the screens already use

        public nonisolated static let blue = accent
        public nonisolated static let green = success
        public nonisolated static let orange = caution
        public nonisolated static let red = error
        public nonisolated static let purple = indigo
        public static let gray = Color(uiColor: .systemGray)
        public static let teal = Color(uiColor: .systemTeal)
        public nonisolated static let label = text
        /// Secondary text: row values, notes and footers.
        public nonisolated static let label2 = textSecondary
        /// Chevrons and other quiet glyphs.
        public nonisolated static let label3 = textSecondary.opacity(0.7)
        public nonisolated static let separator = hairline
        public nonisolated static let window = pageBackground
        public nonisolated static let pane = pageBackground
        public static let fill = Color(uiColor: .tertiarySystemFill)
        public nonisolated static let selection = accent.opacity(0.16)
        public static let glass: Material = .regular
        public static let popover: Material = .regular

        public typealias Space = IOSDesignScale.Space
        public typealias Radius = IOSDesignScale.Radius
        public typealias Stroke = IOSDesignScale.Stroke
        public typealias TypeSize = IOSDesignScale.TypeSize
        public typealias Grid = IOSDesignScale.Grid

        // MARK: Type

        // Native iOS text roles replace Mac's smaller reading sizes: 12/13/16/17/17 pt at default text size.
        public static let caption: Font = .caption
        public static let note: Font = .footnote
        public static let small: Font = .callout
        public static let body = Font(face: DesignSheet.IOS.body)
        public static let heading: Font = .headline
        /// "Tunnels" and "Settings" on the first screen: subheadline bold.
        public static let firstScreenHeading = Font(face: DesignSheet.IOS.firstScreenHeading)
        /// Group headings on every other page: footnote semibold.
        public static let groupHeading = Font(face: DesignSheet.IOS.groupHeading)
        /// Group footers and notes under a row: footnote.
        public static let footer = Font(face: DesignSheet.IOS.caption)
        /// Compact button titles: subheadline semibold.
        public static let button = Font(face: DesignSheet.IOS.button)
        /// Labels and field text of a form on the grid: subheadline.
        public static let field = Font(face: DesignSheet.IOS.field)
        /// Keys and addresses: footnote, monospaced.
        public static let key = Font(face: DesignSheet.IOS.key).monospaced()
        /// A sheet's title under its toolbar: title2 bold.
        public static let sheetTitle = Font(face: DesignSheet.IOS.sheetTitle)
    }

    public extension Color {
        /// A colour that resolves to the pair's light or dark value with the appearance.
        nonisolated init(sheet pair: DesignSheet.Pair) {
            self.init(uiColor: UIColor { traits in
                let colour = pair.value(dark: traits.userInterfaceStyle == .dark)
                return UIColor(red: colour.red, green: colour.green, blue: colour.blue, alpha: colour.opacity)
            })
        }
    }

    public extension Font {
        /// The sheet face as a Dynamic Type role at its weight.
        nonisolated init(face: DesignSheet.IOSFace) {
            let style: Font.TextStyle = switch face.role {
            case .title2: .title2
            case .body: .body
            case .subheadline: .subheadline
            case .footnote: .footnote
            case .caption: .caption
            }
            let weight: Font.Weight = switch face.weight {
            case "bold": .bold
            case "semibold": .semibold
            default: .regular
            }
            self = .system(style, weight: weight)
        }
    }

    package extension View {
        /// The sheet's card: card fill, a 0.5 pt card border and radius 10.
        func iosCard(padding: CGFloat = IOSDesign.Space.section) -> some View {
            self.padding(padding)
                .background(IOSDesign.card, in: .rect(cornerRadius: IOSDesign.Radius.card))
                .overlay {
                    RoundedRectangle(cornerRadius: IOSDesign.Radius.card)
                        .strokeBorder(IOSDesign.cardBorder, lineWidth: IOSDesign.Stroke.card)
                }
        }

        /// A system grouped form on the sheet's page background, tinted accent. Pages restyled to layout C use
        /// ``IOSCardFormStyle`` instead.
        func iosGroupedForm() -> some View {
            formStyle(.grouped)
                .font(IOSDesign.body)
                .tint(IOSDesign.accent)
                .scrollContentBackground(.hidden)
                .background(IOSDesign.pageBackground)
        }
    }
#endif
