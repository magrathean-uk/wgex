// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI

    /// The design sheet's buttons: primary (gradient, for the one thing to press), secondary (tinted) and destructive (red text).
    /// A secondary button whose role is destructive takes the destructive look.
    public struct MacSheetButtonStyle: ButtonStyle {
        public enum Kind: Sendable {
            case primary, secondary, destructive
        }

        private let kind: Kind

        public init(_ kind: Kind) {
            self.kind = kind
        }

        public func makeBody(configuration: Configuration) -> some View {
            MacSheetButtonBody(
                label: configuration.label, kind: configuration.role == .destructive && kind == .secondary ? .destructive : kind,
                pressed: configuration.isPressed,
            )
        }
    }

    public extension ButtonStyle where Self == MacSheetButtonStyle {
        /// Solid accent-to-indigo gradient with onAccent text.
        static var macPrimary: MacSheetButtonStyle {
            MacSheetButtonStyle(.primary)
        }

        /// Accent at 12% with a 0.8 pt accent border and accent text.
        static var macSecondary: MacSheetButtonStyle {
            MacSheetButtonStyle(.secondary)
        }

        /// Error-colour text, no fill.
        static var macDestructive: MacSheetButtonStyle {
            MacSheetButtonStyle(.destructive)
        }
    }

    private struct MacSheetButtonBody<Label: View>: View {
        let label: Label
        let kind: MacSheetButtonStyle.Kind
        let pressed: Bool
        @Environment(\.isEnabled) private var isEnabled

        private var shape: RoundedRectangle {
            RoundedRectangle(cornerRadius: MacDesign.Radius.control)
        }

        var body: some View {
            label
                .font(MacDesign.button)
                .foregroundStyle(foreground)
                .padding(.vertical, 4).padding(.horizontal, MacFieldRowMetrics.unfilledButtonInset)
                .background { fill }
                .overlay {
                    if kind == .secondary {
                        shape.strokeBorder(
                            MacDesign.accent.opacity(DesignSheet.Parts.secondaryBorderOpacity), lineWidth: MacDesign.Stroke.button,
                        )
                    }
                }
                .contentShape(shape)
                .opacity(isEnabled ? (pressed ? 0.72 : 1) : 0.45)
        }

        private var foreground: Color {
            switch kind {
            case .primary: MacDesign.onAccent
            case .secondary: MacDesign.accent
            case .destructive: MacDesign.error
            }
        }

        @ViewBuilder private var fill: some View {
            switch kind {
            case .primary:
                shape.fill(LinearGradient(
                    colors: [MacDesign.accent, MacDesign.indigo], startPoint: .topLeading, endPoint: .bottomTrailing,
                ))
            case .secondary:
                shape.fill(MacDesign.accent.opacity(DesignSheet.Parts.secondaryFillOpacity))
            case .destructive:
                Color.clear
            }
        }
    }

    /// A page of cards (layout A): an optional page title, then each form section as a group heading, a card whose rows are
    /// divided by hairlines, and a caption footer. `Form { Section … }` keeps its structure; only the look changes.
    public struct MacCardFormStyle: FormStyle {
        private let title: String?

        public init(title: String? = nil) {
            self.title = title
        }

        public func makeBody(configuration: Configuration) -> some View {
            ScrollView {
                VStack(alignment: .leading, spacing: MacDesign.Space.groupGap) {
                    if let title {
                        MacPageTitle(title)
                    }
                    ForEach(sections: configuration.content) { section in
                        MacCardGroup(section: section)
                    }
                }
                .padding(MacDesign.Space.page)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollContentBackground(.hidden)
            .background(MacDesign.pageBackground)
            .labeledContentStyle(MacRowLabeledContentStyle())
            .font(MacDesign.body)
            .foregroundStyle(MacDesign.text)
        }
    }

    public extension FormStyle where Self == MacCardFormStyle {
        /// Cards without a page title (sheets).
        static var macCards: MacCardFormStyle {
            MacCardFormStyle()
        }

        /// Cards under a 17 pt bold page title.
        static func macCards(title: String) -> MacCardFormStyle {
            MacCardFormStyle(title: title)
        }
    }

    private struct MacCardGroup: View {
        let section: SectionConfiguration

        var body: some View {
            VStack(alignment: .leading, spacing: 4) {
                if !section.header.isEmpty {
                    section.header
                        .font(MacDesign.groupHeading).foregroundStyle(MacDesign.textSecondary)
                        .padding(.horizontal, 4)
                }
                if !section.content.isEmpty {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(section.content) { row in
                            row
                                .padding(.vertical, MacDesign.Space.rowVertical)
                                .padding(.horizontal, MacDesign.Space.rowHorizontal)
                                .frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
                                .overlay(alignment: .top) {
                                    if row.id != section.content.first?.id {
                                        Rectangle().fill(MacDesign.hairline).frame(height: 0.5)
                                            .padding(.leading, MacDesign.Space.rowHorizontal)
                                    }
                                }
                        }
                    }
                    .macCard(padding: 0)
                }
                if !section.footer.isEmpty {
                    section.footer
                        .font(MacDesign.caption).foregroundStyle(MacDesign.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }
            }
        }
    }

    /// A card row: the label (and any note under it, in caption) on the left, the value on the right in textSecondary.
    public struct MacRowLabeledContentStyle: LabeledContentStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            HStack(alignment: .center, spacing: 12) {
                MacRowLabel { configuration.label }
                Spacer(minLength: 12)
                configuration.content.foregroundStyle(MacDesign.textSecondary)
            }
        }
    }

    /// The first text of a label in body, every later text as a caption note in textSecondary.
    package struct MacRowLabel<Content: View>: View {
        private let content: Content

        package init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        package var body: some View {
            Group(subviews: content) { lines in
                VStack(alignment: .leading, spacing: 1) {
                    if let first = lines.first {
                        first.foregroundStyle(MacDesign.text)
                    }
                    ForEach(lines.dropFirst()) { note in
                        note.font(MacDesign.caption).foregroundStyle(MacDesign.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    /// A settings row whose control (a switch or a pop-up) sits on the right. The visible label is hidden from accessibility:
    /// the control keeps its own label and identifier.
    package struct MacControlRow<Label: View, Control: View>: View {
        private let label: Label
        private let control: Control

        package init(@ViewBuilder control: () -> Control, @ViewBuilder label: () -> Label) {
            self.control = control()
            self.label = label()
        }

        package var body: some View {
            HStack(alignment: .center, spacing: 12) {
                MacRowLabel { label }.accessibilityHidden(true)
                Spacer(minLength: 12)
                control
            }
        }
    }

    /// A text-field row: the visible label on the left, the field on the right in the system's bordered field (so it reads as
    /// editable), at most 340 pt wide so the fields of a card share one right-hand column (``MacFieldRowMetrics/keyWidth``
    /// for a field that holds a whole key). The visible label is hidden from accessibility: the field keeps its own label and
    /// identifier.
    package struct MacFieldRow<Label: View, Field: View>: View {
        private let label: Label
        private let field: Field
        private let fieldWidth: CGFloat

        package init(
            fieldWidth: CGFloat = MacFieldRowMetrics.fieldWidth, @ViewBuilder field: () -> Field, @ViewBuilder label: () -> Label,
        ) {
            self.fieldWidth = fieldWidth
            self.field = field()
            self.label = label()
        }

        package var body: some View {
            HStack(alignment: .center, spacing: 12) {
                MacRowLabel { label }.accessibilityHidden(true).layoutPriority(1)
                Spacer(minLength: 12)
                field
                    .textFieldStyle(.roundedBorder)
                    .foregroundStyle(MacDesign.text)
                    .frame(maxWidth: fieldWidth)
            }
        }
    }

    package enum MacFieldRowMetrics {
        /// The right-hand column of a card's text fields.
        package static let fieldWidth: CGFloat = 340
        /// A field for a whole 44-character WireGuard key in 13 pt monospaced type, with room to spare.
        package static let keyWidth: CGFloat = 420
        /// The horizontal padding of a sheet button: a button without a fill (destructive) moves out by this much so its text
        /// lines up with the edge of the fields.
        package static let unfilledButtonInset: CGFloat = 12
    }

    /// A caption under a row (a note, or a message about the value): textSecondary, or the error or caution colour.
    package struct MacRowCaption: View {
        package enum Tone: Sendable {
            case note, error, caution
        }

        private let text: String
        private let tone: Tone

        package init(_ text: String, tone: Tone = .note) {
            self.text = text
            self.tone = tone
        }

        package var body: some View {
            Text(text).font(MacDesign.caption).foregroundStyle(colour).fixedSize(horizontal: false, vertical: true)
        }

        private var colour: Color {
            switch tone {
            case .note: MacDesign.textSecondary
            case .error: MacDesign.error
            case .caution: MacDesign.caution
            }
        }
    }

    /// The page title: 17 pt bold in the text colour.
    package struct MacPageTitle: View {
        private let title: String

        package init(_ title: String) {
            self.title = title
        }

        package var body: some View {
            Text(title).font(MacDesign.pageTitle).foregroundStyle(MacDesign.text).lineLimit(1).truncationMode(.middle)
                .accessibilityAddTraits(.isHeader)
        }
    }

    /// A sidebar heading ("Tunnels", "Settings"): 12 pt bold in the text colour over a 1 pt rule.
    package struct MacSidebarHeading: View {
        private let title: String

        package init(_ title: String) {
            self.title = title
        }

        package var body: some View {
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(MacDesign.sidebarHeading).foregroundStyle(MacDesign.text).lineLimit(1)
                Rectangle().fill(MacDesign.cardBorder).frame(height: MacDesign.Stroke.sidebarHeadingRule)
            }
            .textCase(nil)
        }
    }
#endif
