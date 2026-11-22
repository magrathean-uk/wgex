// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI

    // MARK: Row kinds

    /// How a row joins the row above it in a card: a `row` starts a new line of the grid under a hairline; a
    /// `continuation` (a second address, an action row) carries on the row above without a hairline; a `caption` is a note
    /// under the row above, without a hairline or a minimum height.
    public enum IOSRowKind: Sendable, Hashable {
        case row, continuation, caption

        /// The padding above a row of this kind in a card: the row padding, a step less for a continuation (the grid's
        /// tight row), none for a caption.
        package var topPadding: CGFloat {
            switch self {
            case .row: IOSDesign.Space.rowVertical
            case .continuation: IOSDesign.Space.rowVertical - IOSDesign.Grid.step
            case .caption: 0
            }
        }
    }

    // SwiftFormat does not recognise declarations expanded by @Entry.
    // swiftformat:disable docComments
    package extension ContainerValues {
        /// The kind of row a card subview is; ``IOSCardRows``, ``IOSSubRows`` and ``IOSListCardRows`` read it.
        @Entry var iosRowKind: IOSRowKind = .row
    }

    // swiftformat:enable docComments

    public extension View {
        /// Marks this card row as a continuation of the row above or a caption under it, so the card draws no hairline
        /// between them.
        func iosRowKind(_ kind: IOSRowKind) -> some View {
            containerValue(\.iosRowKind, kind)
        }
    }

    // MARK: Columns

    /// The two columns of the form grid: the label column (112 pt at the default text size, growing with Dynamic Type)
    /// and, 8 pt after it, the field column to the row's end. Every row of a form uses the same lines, so fields start and
    /// end on one vertical line. Labels stay on one line; at accessibility text sizes the content goes under its label.
    /// The visible label is hidden from accessibility: the control keeps its own label and identifier.
    package struct IOSGridColumns<Label: View, Content: View>: View {
        private let label: Label
        private let content: Content
        private let onLabelTap: (() -> Void)?
        @Environment(\.dynamicTypeSize) private var typeSize
        @ScaledMetric(relativeTo: .subheadline) private var labelColumn = IOSDesign.Grid.labelColumn

        package init(onLabelTap: (() -> Void)? = nil, @ViewBuilder label: () -> Label, @ViewBuilder content: () -> Content) {
            self.onLabelTap = onLabelTap
            self.label = label()
            self.content = content()
        }

        package var body: some View {
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: IOSDesign.Grid.step) {
                    rowLabel
                    content
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(alignment: .center, spacing: IOSDesign.Grid.columnGap) {
                    rowLabel.frame(width: labelColumn, alignment: .leading)
                    content.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }

        @ViewBuilder private var rowLabel: some View {
            // One line; a label longer than the column ("DNS match domains") shrinks a little rather than wrap.
            let text = IOSRowLabel { label }.font(IOSDesign.field).lineLimit(1).minimumScaleFactor(IOSGridLabel.shrink)
                .accessibilityHidden(true)
            if let onLabelTap {
                text.contentShape(.rect).onTapGesture(perform: onLabelTap)
            } else {
                text
            }
        }
    }

    private enum IOSGridLabel {
        /// The least a grid label shrinks to stay on one line.
        static let shrink: CGFloat = 0.8
    }

    // MARK: Field rows

    /// A text-field row on the grid: the label in the label column, the field in a box that fills the field column (36 pt
    /// high at the default text size, radius 8, the fill colour, text inset 10), with an optional accessory (a remove
    /// glyph, a unit) at the box's right end. A tap anywhere on the row (label, box or padding) focuses the field: by
    /// default the row binds the field's focus itself; a field whose focus its owner already binds passes `onTap` instead.
    public struct IOSFieldRow<Label: View, Field: View, Accessory: View>: View {
        private let label: Label
        private let field: Field
        private let accessory: Accessory
        private let onTap: (() -> Void)?
        @FocusState private var focused: Bool

        public init(
            onTap: (() -> Void)? = nil, @ViewBuilder field: () -> Field, @ViewBuilder accessory: () -> Accessory,
            @ViewBuilder label: () -> Label,
        ) {
            self.onTap = onTap
            self.field = field()
            self.accessory = accessory()
            self.label = label()
        }

        public var body: some View {
            IOSGridColumns(onLabelTap: focus) { label } content: {
                IOSFieldBox(onTap: focus) { focusableField } accessory: { accessory }
            }
            .iosRowTapArea(perform: focus)
        }

        @ViewBuilder private var focusableField: some View {
            if onTap == nil {
                field.focused($focused)
            } else {
                field
            }
        }

        private func focus() {
            if let onTap {
                onTap()
            } else {
                focused = true
            }
        }
    }

    public extension IOSFieldRow where Accessory == EmptyView {
        init(onTap: (() -> Void)? = nil, @ViewBuilder field: () -> Field, @ViewBuilder label: () -> Label) {
            self.init(onTap: onTap, field: field, accessory: { EmptyView() }, label: label)
        }
    }

    /// The field box of the grid; a tap on the box around the text runs `onTap`.
    private struct IOSFieldBox<Field: View, Accessory: View>: View {
        let onTap: () -> Void
        let field: Field
        let accessory: Accessory
        @ScaledMetric(relativeTo: .subheadline) private var height = IOSDesign.Grid.fieldHeight

        init(onTap: @escaping () -> Void, @ViewBuilder field: () -> Field, @ViewBuilder accessory: () -> Accessory) {
            self.onTap = onTap
            self.field = field()
            self.accessory = accessory()
        }

        var body: some View {
            HStack(spacing: IOSDesign.Grid.columnGap) {
                field.frame(maxWidth: .infinity, alignment: .leading)
                accessory
            }
            .font(IOSDesign.field).foregroundStyle(IOSDesign.text)
            .padding(.horizontal, IOSDesign.Grid.fieldInset).padding(.vertical, IOSDesign.Grid.step)
            .frame(maxWidth: .infinity, minHeight: height, alignment: .leading)
            .background {
                // Behind the field, so a tap on the box around the text focuses it too.
                RoundedRectangle(cornerRadius: IOSDesign.Grid.fieldRadius).fill(IOSDesign.fill).onTapGesture(perform: onTap)
            }
        }
    }

    /// A unit at the right end of a field box ("seconds"): footnote in textSecondary, hidden from accessibility (the
    /// field's own label names the unit).
    public struct IOSFieldUnit: View {
        private let text: String

        public init(_ text: String) {
            self.text = text
        }

        public var body: some View {
            Text(text).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary).lineLimit(1).fixedSize()
                .accessibilityHidden(true)
        }
    }

    // MARK: Value rows

    /// A read-only row on the grid: the label in the label column, the value in the field column at the field text inset,
    /// without a fill, in textSecondary, one line shortened in the middle unless the value sets its own line limit (a
    /// revealed key wraps), with an optional accessory (icon buttons) at the field column's right end, centred on the
    /// value's first line.
    public struct IOSValueRow<Label: View, Value: View, Accessory: View>: View {
        private let label: Label
        private let value: Value
        private let accessory: Accessory
        @ScaledMetric(relativeTo: .subheadline) private var height = IOSDesign.Grid.fieldHeight

        public init(@ViewBuilder value: () -> Value, @ViewBuilder accessory: () -> Accessory, @ViewBuilder label: () -> Label) {
            self.value = value()
            self.accessory = accessory()
            self.label = label()
        }

        public var body: some View {
            IOSGridColumns { label } content: {
                HStack(alignment: .iosFirstLine, spacing: IOSDesign.Grid.buttonGap) {
                    value.font(IOSDesign.field).foregroundStyle(IOSDesign.textSecondary).lineLimit(1).truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .alignmentGuide(.iosFirstLine) { size in
                            // The middle of the first line: its baseline plus the descent, halved.
                            (size[.firstTextBaseline] + size.height - size[.lastTextBaseline]) / 2
                        }
                    accessory.alignmentGuide(.iosFirstLine) { size in size[VerticalAlignment.center] }
                }
                .padding(.leading, IOSDesign.Grid.fieldInset)
                .frame(maxWidth: .infinity, minHeight: height, alignment: .leading)
            }
        }
    }

    private extension VerticalAlignment {
        /// The middle of a value row's first line of text, on which its icon buttons sit.
        enum IOSFirstLine: AlignmentID {
            static func defaultValue(in context: ViewDimensions) -> CGFloat {
                context[VerticalAlignment.center]
            }
        }

        static let iosFirstLine = VerticalAlignment(IOSFirstLine.self)
    }

    public extension IOSValueRow where Accessory == EmptyView {
        init(@ViewBuilder value: () -> Value, @ViewBuilder label: () -> Label) {
            self.init(value: value, accessory: { EmptyView() }, label: label)
        }
    }

    // MARK: Action rows

    /// Compact buttons in the field column, left-aligned on the field line, 8 pt apart, secondary unless a button sets its
    /// own style; when they do not fit on one line they go one under the other, 8 pt apart. The buttons sit in a band a
    /// field box high, so a continuation row puts them 6 pt under the field above, as the grid draws. Without a label the
    /// row continues the row above (no hairline, pulled up a step).
    public struct IOSActionRow<Label: View, Content: View>: View {
        private let label: Label
        private let content: Content
        private let continues: Bool

        public init(@ViewBuilder content: () -> Content, @ViewBuilder label: () -> Label) {
            self.content = content()
            self.label = label()
            continues = false
        }

        public var body: some View {
            IOSGridColumns { label } content: {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: IOSDesign.Grid.buttonGap) { content }
                    VStack(alignment: .leading, spacing: IOSDesign.Grid.buttonGap) { content }
                }
                .padding(.vertical, (IOSDesign.Grid.fieldHeight - IOSDesign.Grid.buttonHeight) / 2)
            }
            .buttonStyle(.iosSecondary)
            .iosRowKind(continues ? .continuation : .row)
        }
    }

    public extension IOSActionRow where Label == EmptyView {
        init(@ViewBuilder content: () -> Content) {
            self.content = content()
            label = EmptyView()
            continues = true
        }
    }

    // MARK: Icon buttons

    /// A 32 pt square icon button (radius 8, the secondary look) whose hit area is 44 pt high and reaches half the 8 pt gap
    /// to each side (40 pt wide), so two icon buttons side by side never share a tap; the button keeps its title as its
    /// accessibility label.
    public struct IOSIconButtonStyle: ButtonStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            IOSIconButtonBody(label: configuration.label, pressed: configuration.isPressed)
        }
    }

    public extension ButtonStyle where Self == IOSIconButtonStyle {
        /// The secondary look as a 32 pt square around the button's symbol.
        static var iosIcon: IOSIconButtonStyle {
            IOSIconButtonStyle()
        }
    }

    private struct IOSIconButtonBody<Label: View>: View {
        let label: Label
        let pressed: Bool
        @Environment(\.isEnabled) private var isEnabled
        @ScaledMetric(relativeTo: .subheadline) private var side = IOSDesign.Grid.iconButton

        var body: some View {
            let shape = RoundedRectangle(cornerRadius: IOSDesign.Radius.button)
            label
                .labelStyle(.iconOnly)
                .font(IOSDesign.button)
                .foregroundStyle(IOSDesign.accent)
                .frame(width: side, height: side)
                .background { shape.fill(IOSDesign.accent.opacity(DesignSheet.Parts.secondaryFillOpacity)) }
                .overlay {
                    shape.strokeBorder(
                        IOSDesign.accent.opacity(DesignSheet.Parts.secondaryBorderOpacity), lineWidth: IOSDesign.Stroke.button,
                    )
                }
                .iosTouchTarget(height: side, width: side, sideReach: IOSDesign.Grid.buttonGap / 2)
                .opacity(isEnabled ? (pressed ? 0.72 : 1) : 0.45)
        }
    }

    // MARK: Glyph buttons

    /// An inline glyph button in a field box (an address's remove glyph): the symbol alone in a 20 pt square at the
    /// default text size, its hit area widened to a 44 pt touch target; the button keeps its title as its accessibility
    /// label. The caller sets the colour.
    public struct IOSGlyphButtonStyle: ButtonStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            IOSGlyphButtonBody(label: configuration.label, pressed: configuration.isPressed)
        }
    }

    public extension ButtonStyle where Self == IOSGlyphButtonStyle {
        /// The symbol alone in a 20 pt square with a 44 pt hit area.
        static var iosGlyph: IOSGlyphButtonStyle {
            IOSGlyphButtonStyle()
        }
    }

    private struct IOSGlyphButtonBody<Label: View>: View {
        let label: Label
        let pressed: Bool
        @Environment(\.isEnabled) private var isEnabled
        @ScaledMetric(relativeTo: .subheadline) private var side = IOSDesign.Grid.glyph

        var body: some View {
            label
                .labelStyle(.iconOnly)
                .frame(width: side, height: side)
                .iosTouchTarget(height: side, width: side)
                .opacity(isEnabled ? (pressed ? 0.72 : 1) : 0.45)
        }
    }

    // MARK: Compact labels

    /// A compact button's icon and title, one step (4 pt) apart, instead of the system label's wide gap.
    public struct IOSCompactLabelStyle: LabelStyle {
        public init() {}

        public func makeBody(configuration: Configuration) -> some View {
            HStack(spacing: IOSDesign.Grid.step) {
                configuration.icon
                configuration.title
            }
        }
    }

    public extension LabelStyle where Self == IOSCompactLabelStyle {
        /// Icon and title one step apart.
        static var iosCompact: IOSCompactLabelStyle {
            IOSCompactLabelStyle()
        }
    }

    // MARK: System controls on the grid

    package extension View {
        /// A pop-up picker on a grid row: its own label hidden (the row shows it), and its chevron let out to the field
        /// column's right line.
        func iosMenuPicker() -> some View {
            labelsHidden().padding(.trailing, -IOSDesign.Grid.menuInset)
        }
    }

    // MARK: Touch targets

    package extension View {
        /// Widens this compact control's hit area to a touch target (44 pt) without changing its layout. Pass `width` for
        /// a control narrower than a touch target (a text button is wide enough already), and `sideReach` to stop the
        /// widening short, where a neighbour sits closer than the touch target would reach.
        func iosTouchTarget(height: CGFloat, width: CGFloat? = nil, sideReach: CGFloat = .infinity) -> some View {
            let vertical = max(0, (IOSDesignScale.minimumTouchHeight - height) / 2)
            let horizontal = min(sideReach, width.map { max(0, (IOSDesignScale.minimumTouchHeight - $0) / 2) } ?? 0)
            let insets = EdgeInsets(top: vertical, leading: horizontal, bottom: vertical, trailing: horizontal)
            return padding(insets).contentShape(.rect)
                .padding(EdgeInsets(top: -vertical, leading: -horizontal, bottom: -vertical, trailing: -horizontal))
        }
    }
#endif
