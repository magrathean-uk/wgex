// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI

    // MARK: Buttons

    /// The sheet's compact buttons: primary (gradient, only a sheet's default action), secondary (tinted) and destructive
    /// (error text); subheadline semibold, radius 8, 32 pt tall at the default text size with 12 pt side padding, and a hit
    /// area that still reaches 44 pt. A secondary button whose role is destructive looks destructive.
    public struct IOSSheetButtonStyle: ButtonStyle {
        public enum Kind: Sendable {
            case primary, secondary, destructive
        }

        private let kind: Kind

        public init(_ kind: Kind) {
            self.kind = kind
        }

        public func makeBody(configuration: Configuration) -> some View {
            IOSSheetButtonBody(
                label: configuration.label, kind: configuration.role == .destructive && kind == .secondary ? .destructive : kind,
                pressed: configuration.isPressed,
            )
        }
    }

    public extension ButtonStyle where Self == IOSSheetButtonStyle {
        /// Solid accent-to-indigo gradient with onAccent text.
        static var iosPrimary: IOSSheetButtonStyle {
            IOSSheetButtonStyle(.primary)
        }

        /// Accent at 12% with a 0.8 pt accent border at 30% and accent text.
        static var iosSecondary: IOSSheetButtonStyle {
            IOSSheetButtonStyle(.secondary)
        }

        /// Error-colour text, no fill.
        static var iosDestructive: IOSSheetButtonStyle {
            IOSSheetButtonStyle(.destructive)
        }
    }

    private struct IOSSheetButtonBody<Label: View>: View {
        let label: Label
        let kind: IOSSheetButtonStyle.Kind
        let pressed: Bool
        @Environment(\.isEnabled) private var isEnabled
        @ScaledMetric(relativeTo: .subheadline) private var height = IOSDesign.Grid.buttonHeight

        private var shape: RoundedRectangle {
            RoundedRectangle(cornerRadius: IOSDesign.Radius.button)
        }

        var body: some View {
            label
                .font(IOSDesign.button)
                .foregroundStyle(foreground)
                .multilineTextAlignment(.center)
                // Destructive has no fill or border, so side padding would only push its text off the row's text edge.
                .padding(.vertical, IOSDesign.Grid.step).padding(.horizontal, kind == .destructive ? 0 : IOSDesign.Grid.buttonPadding)
                .frame(minHeight: height)
                .background { fill }
                .overlay {
                    if kind == .secondary {
                        shape.strokeBorder(
                            IOSDesign.accent.opacity(DesignSheet.Parts.secondaryBorderOpacity), lineWidth: IOSDesign.Stroke.button,
                        )
                    }
                }
                .iosTouchTarget(height: height)
                .opacity(isEnabled ? (pressed ? 0.72 : 1) : 0.45)
        }

        private var foreground: Color {
            switch kind {
            case .primary: IOSDesign.onAccent
            case .secondary: IOSDesign.accent
            case .destructive: IOSDesign.error
            }
        }

        @ViewBuilder private var fill: some View {
            switch kind {
            case .primary:
                shape.fill(LinearGradient(
                    colors: [IOSDesign.accent, IOSDesign.indigo], startPoint: .topLeading, endPoint: .bottomTrailing,
                ))
            case .secondary:
                shape.fill(IOSDesign.accent.opacity(DesignSheet.Parts.secondaryFillOpacity))
            case .destructive:
                Color.clear
            }
        }
    }

    /// A button or navigation link that is a whole card row: `action` shows its title in accent (error for a destructive
    /// role) as a list button does; `link` shows it in the text colour with a chevron, as a list navigation link does.
    /// Inside an ``IOSCardRows`` card the whole row, padding included, answers a tap and shows the press.
    public struct IOSRowButtonStyle: ButtonStyle {
        public enum Kind: Sendable {
            case action, link
        }

        private let kind: Kind

        public init(_ kind: Kind) {
            self.kind = kind
        }

        public func makeBody(configuration: Configuration) -> some View {
            IOSRowButtonBody(
                label: configuration.label, kind: kind, destructive: configuration.role == .destructive,
                pressed: configuration.isPressed,
            )
        }
    }

    private struct IOSRowButtonBody<Label: View>: View {
        let label: Label
        let kind: IOSRowButtonStyle.Kind
        let destructive: Bool
        let pressed: Bool
        @Environment(\.iosCardRowPadding) private var rowPadding

        var body: some View {
            let padding = rowPadding ?? EdgeInsets()
            HStack(spacing: IOSDesign.Space.medium) {
                label
                    .labeledContentStyle(IOSRowLabeledContentStyle())
                    .frame(maxWidth: .infinity, alignment: .leading)
                if kind == .link {
                    Image(systemName: "chevron.right")
                        .font(IOSDesign.footer.weight(.semibold))
                        .foregroundStyle(IOSDesign.label3)
                        .accessibilityHidden(true)
                }
            }
            .foregroundStyle(kind == .link ? IOSDesign.text : destructive ? IOSDesign.error : IOSDesign.accent)
            // A whole row, not a compact button: the row's height between its padding, so with the padding below the hit
            // area and press fill cover the whole 44 pt row.
            .frame(minHeight: IOSDesignScale.minimumTouchHeight - 2 * IOSDesign.Space.rowVertical)
            // The button owns the row's padding (in a card or a List card row): its hit area and press fill cover the whole
            // row (the card clips the fill to its corners), while the negative padding leaves the row's layout as it was.
            .padding(padding)
            .contentShape(.rect)
            .background { Rectangle().fill(pressed ? IOSDesign.hairline : .clear) }
            .padding(padding.negated)
        }
    }

    public extension ButtonStyle where Self == IOSRowButtonStyle {
        /// A card row that acts: accent title, error for a destructive role.
        static var iosRowAction: IOSRowButtonStyle {
            IOSRowButtonStyle(.action)
        }

        /// A card row that opens a page: text-colour title (and value) with a chevron.
        static var iosRowLink: IOSRowButtonStyle {
            IOSRowButtonStyle(.link)
        }
    }

    // MARK: Cards

    /// A page of cards (layout C): each form section as a group heading, a card whose rows are divided by hairlines, and a
    /// footnote footer. `Form { Section … }` keeps its structure; buttons default to ``IOSRowButtonStyle/iosRowAction``.
    public struct IOSCardFormStyle: FormStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            ScrollView {
                VStack(alignment: .leading, spacing: IOSDesign.Space.groupGap) {
                    ForEach(sections: configuration.content) { section in
                        IOSCardGroup(section: section)
                    }
                }
                .padding(IOSDesign.Space.page)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollContentBackground(.hidden)
            .background(IOSDesign.pageBackground)
            .labeledContentStyle(IOSRowLabeledContentStyle())
            .toggleStyle(IOSRowToggleStyle())
            .buttonStyle(.iosRowAction)
            .font(IOSDesign.body)
            .foregroundStyle(IOSDesign.text)
            .tint(IOSDesign.accent)
        }
    }

    public extension FormStyle where Self == IOSCardFormStyle {
        /// Grouped cards on the page background.
        static var iosCards: IOSCardFormStyle {
            IOSCardFormStyle()
        }
    }

    private struct IOSCardGroup: View {
        let section: SectionConfiguration

        var body: some View {
            VStack(alignment: .leading, spacing: IOSDesign.Space.small) {
                if !section.header.isEmpty {
                    IOSGroupHeading { section.header }
                }
                if !section.content.isEmpty {
                    IOSCardRows { section.content }
                }
                if !section.footer.isEmpty {
                    section.footer
                        .font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }
            }
        }
    }

    // SwiftFormat does not recognise declarations expanded by @Entry.
    // swiftformat:disable docComments
    package extension EnvironmentValues {
        /// The padding ``IOSCardRows`` or a List card row (``View/iosCardRow(_:selected:divider:)``) puts round the row a
        /// view is in, nil outside a card. A control that fills its row reads it to take the padding into its hit area.
        @Entry var iosCardRowPadding: EdgeInsets? = nil
    }

    // swiftformat:enable docComments

    private extension EdgeInsets {
        /// The card row's padding: 6 pt above and below, 12 pt left and right.
        static var iosCardRow: EdgeInsets {
            EdgeInsets(
                top: IOSDesign.Space.rowVertical, leading: IOSDesign.Space.rowHorizontal,
                bottom: IOSDesign.Space.rowVertical, trailing: IOSDesign.Space.rowHorizontal,
            )
        }

        var negated: EdgeInsets {
            EdgeInsets(top: -top, leading: -leading, bottom: -bottom, trailing: -trailing)
        }
    }

    package extension View {
        /// Inside an ``IOSCardRows`` card, takes the row's padding into this view's hit area, so a control that fills its
        /// row answers a tap anywhere in the row; outside a card the view's frame is its hit area. Layout is unchanged.
        func iosRowHitArea() -> some View {
            modifier(IOSRowHitArea(action: nil))
        }

        /// Runs `action` for a tap anywhere in the card row around this view that the view itself does not take (a text
        /// field focusing itself, for example); outside a card, for a tap on the view's frame.
        func iosRowTapArea(perform action: @escaping () -> Void) -> some View {
            modifier(IOSRowHitArea(action: action))
        }
    }

    private struct IOSRowHitArea: ViewModifier {
        let action: (() -> Void)?
        @Environment(\.iosCardRowPadding) private var rowPadding

        func body(content: Content) -> some View {
            let padding = rowPadding ?? EdgeInsets()
            if let action {
                // Behind the view, so taps on the view itself stay the view's.
                content.background {
                    Color.clear.contentShape(.rect).onTapGesture(perform: action).padding(padding.negated)
                }
            } else {
                content.padding(padding).contentShape(.rect).padding(padding.negated)
            }
        }
    }

    /// One card of rows outside a form: each subview is a row at least 44 pt tall, padded 12 pt left and right, with a
    /// hairline above every row but the first and those that continue the row above (see ``IOSRowKind``); a continuation
    /// is pulled up a step, as the grid's tight row.
    public struct IOSCardRows<Content: View>: View {
        private let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            Group(subviews: content) { rows in
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(rows) { row in
                        let kind = row.containerValues.iosRowKind
                        let divided = row.id != rows.first?.id && kind == .row
                        let pulled = kind == .continuation ? IOSDesign.Space.rowVertical - kind.topPadding : 0
                        row
                            .environment(\.iosCardRowPadding, .iosCardRow)
                            .padding(.iosCardRow)
                            .padding(.top, -pulled)
                            .frame(maxWidth: .infinity, minHeight: IOSDesignScale.minimumTouchHeight - pulled, alignment: .leading)
                            .overlay(alignment: .top) {
                                if divided {
                                    Rectangle().fill(IOSDesign.hairline).frame(height: IOSDesign.Stroke.hairline)
                                        .padding(.leading, IOSDesign.Space.rowHorizontal)
                                }
                            }
                    }
                }
                .clipShape(.rect(cornerRadius: IOSDesign.Radius.card))
                .iosCard(padding: 0)
            }
        }
    }

    /// A card row: the label (and any note under it, in footnote) on the left, the value on the right in textSecondary with
    /// monospaced digits. At accessibility text sizes the value goes under the label, as the system's labelled rows do.
    public struct IOSRowLabeledContentStyle: LabeledContentStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            IOSRowLabeledContent(label: configuration.label, content: configuration.content)
        }
    }

    private struct IOSRowLabeledContent<Label: View, Content: View>: View {
        let label: Label
        let content: Content
        @Environment(\.dynamicTypeSize) private var typeSize

        var body: some View {
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                    IOSRowLabel { label }
                    value.multilineTextAlignment(.leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(alignment: .center, spacing: IOSDesign.Space.medium) {
                    IOSRowLabel { label }
                    Spacer(minLength: IOSDesign.Space.medium)
                    value.multilineTextAlignment(.trailing)
                }
            }
        }

        private var value: some View {
            content.foregroundStyle(IOSDesign.textSecondary).monospacedDigit()
        }
    }

    /// The first text of a label in body and the text colour, every later text as a footnote note in textSecondary.
    public struct IOSRowLabel<Content: View>: View {
        private let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            Group(subviews: content) { lines in
                VStack(alignment: .leading, spacing: 1) {
                    if let first = lines.first {
                        first.foregroundStyle(IOSDesign.text)
                    }
                    ForEach(lines.dropFirst()) { note in
                        note.font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    /// A switch row: the label as an ``IOSRowLabel`` (a second text becomes the note under it), the system switch on the
    /// right, tinted accent, its track ending on the row's right line (the system switch draws a little past its frame).
    /// The switch keeps the toggle's label, identifier and disabled state.
    public struct IOSRowToggleStyle: ToggleStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            Toggle(isOn: configuration.$isOn) {
                IOSRowLabel { configuration.label }
            }
            .toggleStyle(.switch)
            .tint(IOSDesign.accent)
            .padding(.trailing, IOSDesign.Grid.switchOverhang)
        }
    }

    /// A row whose control (a pop-up picker, a field) sits on the right of its label; at accessibility text sizes the
    /// control goes under the label. The visible label is hidden from accessibility: the control keeps its own label and
    /// identifier.
    public struct IOSControlRow<Label: View, Control: View>: View {
        private let label: Label
        private let control: Control
        @Environment(\.dynamicTypeSize) private var typeSize

        public init(@ViewBuilder control: () -> Control, @ViewBuilder label: () -> Label) {
            self.control = control()
            self.label = label()
        }

        public var body: some View {
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                    IOSRowLabel { label }.accessibilityHidden(true)
                    control
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(alignment: .center, spacing: IOSDesign.Space.medium) {
                    IOSRowLabel { label }.accessibilityHidden(true)
                    Spacer(minLength: IOSDesign.Space.medium)
                    // The control takes its own width first, so a pop-up's value stays on one line instead of wrapping
                    // (a wrapped menu picker outgrows its row).
                    control.layoutPriority(1)
                }
            }
        }
    }

    // MARK: Headings

    /// A first-screen group heading ("Tunnels", "Settings"): subheadline bold in the text colour over a 1 pt rule.
    public struct IOSFirstScreenHeading: View {
        private let title: String

        public init(_ title: String) {
            self.title = title
        }

        public var body: some View {
            VStack(alignment: .leading, spacing: IOSDesign.Space.small) {
                Text(title).font(IOSDesign.firstScreenHeading).foregroundStyle(IOSDesign.text).lineLimit(1)
                    .padding(.horizontal, 4)
                Rectangle().fill(IOSDesign.cardBorder).frame(height: IOSDesign.Stroke.headingRule)
            }
            .textCase(nil)
            .accessibilityAddTraits(.isHeader)
        }
    }

    /// A group heading on every other page: footnote semibold in textSecondary, in the strings' own sentence case.
    public struct IOSGroupHeading<Content: View>: View {
        private let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            content
                .font(IOSDesign.groupHeading).foregroundStyle(IOSDesign.textSecondary)
                .textCase(nil)
                .padding(.horizontal, 4)
                .accessibilityAddTraits(.isHeader)
        }
    }

    public extension IOSGroupHeading where Content == Text {
        init(_ title: String) {
            self.init { Text(title) }
        }
    }

    // MARK: Lists

    /// Where a List row sits in its card, so the row can draw its part of the card.
    public enum IOSCardRowPosition: Sendable, Hashable {
        case only, first, middle, last

        /// The position of row `index` in a card of `count` rows.
        public init(index: Int, count: Int) {
            self = switch (index, count) {
            case (_, ...1): .only
            case (0, _): .first
            case (count - 1, _): .last
            default: .middle
            }
        }
    }

    public extension View {
        /// A List styled as layout C cards: grouped, on the page background, 12 pt between sections, rows at least 44 pt,
        /// values in textSecondary, buttons in accent. Each row then takes ``iosCardRow(_:selected:)``; the List keeps
        /// selection, navigation links, swipe to delete and reordering.
        func iosCardList() -> some View {
            listStyle(.grouped)
                .listSectionSpacing(IOSDesign.Space.groupGap)
                .environment(\.defaultMinListRowHeight, IOSDesignScale.minimumTouchHeight)
                .scrollContentBackground(.hidden)
                .background(IOSDesign.pageBackground)
                .labeledContentStyle(IOSRowLabeledContentStyle())
                .font(IOSDesign.body)
                .tint(IOSDesign.accent)
        }

        /// A List row drawn as its part of a card (card fill, 0.5 pt border, a hairline above all but the first row) with
        /// the sheet's row padding; `selected` tints it accent, as the iPad sidebar shows the open page. Without `divider` the
        /// row continues the one above, with no hairline between them. A row button takes the row padding into its hit
        /// area, as in a card.
        func iosCardRow(_ position: IOSCardRowPosition, selected: Bool = false, divider: Bool = true) -> some View {
            modifier(IOSCardRowModifier(position: position, selected: selected, kind: divider ? .row : .caption))
        }

        /// A List section header or footer at the card's edges (a first-screen heading or a group heading).
        func iosListHeader() -> some View {
            modifier(IOSListHeaderModifier(top: IOSDesign.Space.small, bottom: IOSDesign.Space.small))
        }
    }

    package extension View {
        /// A List card row of the given kind (see ``IOSRowKind``): a continuation has no hairline and is pulled up a step,
        /// a caption has no hairline.
        func iosCardRow(_ position: IOSCardRowPosition, kind: IOSRowKind) -> some View {
            modifier(IOSCardRowModifier(position: position, selected: false, kind: kind))
        }

        /// A group heading of a form on the grid: a step above its card, the space above it set by the list's section
        /// spacing.
        func iosGridHeader() -> some View {
            modifier(IOSListHeaderModifier(top: 0, bottom: IOSDesign.Grid.headingBelow))
        }
    }

    // SwiftFormat does not recognise declarations expanded by @Entry.
    // swiftformat:disable docComments
    package extension EnvironmentValues {
        /// Extra space on each side of a List's cards, so a form's cards stop at the grid's form width (iPad) while the List
        /// itself, and so its scrolling, stays the container's full width.
        @Entry var iosListSideInset: CGFloat = 0
    }

    // swiftformat:enable docComments

    private struct IOSCardRowModifier: ViewModifier {
        let position: IOSCardRowPosition
        let selected: Bool
        let kind: IOSRowKind
        @Environment(\.iosListSideInset) private var side

        func body(content: Content) -> some View {
            let edge = IOSDesign.Space.page + side
            content
                .environment(\.iosCardRowPadding, .iosCardRow)
                .listRowInsets(EdgeInsets(
                    top: kind == .continuation ? kind.topPadding : IOSDesign.Space.rowVertical,
                    leading: edge + IOSDesign.Space.rowHorizontal,
                    bottom: IOSDesign.Space.rowVertical, trailing: edge + IOSDesign.Space.rowHorizontal,
                ))
                .listRowSeparator(.hidden)
                .listRowBackground(IOSCardRowBackground(position: position, selected: selected, divider: kind == .row, edge: edge))
        }
    }

    private struct IOSListHeaderModifier: ViewModifier {
        let top: CGFloat
        let bottom: CGFloat
        @Environment(\.iosListSideInset) private var side

        func body(content: Content) -> some View {
            content.listRowInsets(EdgeInsets(
                top: top, leading: IOSDesign.Space.page + side, bottom: bottom, trailing: IOSDesign.Space.page + side,
            ))
        }
    }

    /// One row's part of a card: the rounded rectangle runs past the row's open edges and is cut at the row, so the rows
    /// of a section join into one bordered card.
    private struct IOSCardRowBackground: View {
        let position: IOSCardRowPosition
        let selected: Bool
        let divider: Bool
        /// From the List's edge to the card's.
        let edge: CGFloat

        var body: some View {
            let radius = IOSDesign.Radius.card
            let extendsUp = position == .middle || position == .last
            let extendsDown = position == .middle || position == .first
            ZStack {
                RoundedRectangle(cornerRadius: radius).fill(IOSDesign.card)
                if selected {
                    RoundedRectangle(cornerRadius: radius).fill(IOSDesign.selection)
                }
                RoundedRectangle(cornerRadius: radius).strokeBorder(IOSDesign.cardBorder, lineWidth: IOSDesign.Stroke.card)
            }
            .padding(.top, extendsUp ? -radius * 2 : 0)
            .padding(.bottom, extendsDown ? -radius * 2 : 0)
            .clipped()
            .overlay(alignment: .top) {
                if extendsUp, divider {
                    Rectangle().fill(IOSDesign.hairline).frame(height: IOSDesign.Stroke.hairline)
                        .padding(.leading, IOSDesign.Space.rowHorizontal)
                }
            }
            .padding(.horizontal, edge)
        }
    }
#endif
