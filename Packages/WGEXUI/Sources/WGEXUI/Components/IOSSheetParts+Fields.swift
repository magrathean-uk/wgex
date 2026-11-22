// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI

    // MARK: Editor rows

    /// The placeholder of a field in an ``IOSFieldRow``: the given text in textSecondary.
    public func iosFieldPrompt(_ text: String) -> Text {
        Text(text).foregroundStyle(IOSDesign.textSecondary)
    }

    /// A caption under a row (a note, or a message about the value): footnote in textSecondary, or the error or caution
    /// colour. In a card it joins the row above without a hairline.
    public struct IOSRowCaption: View {
        public enum Tone: Sendable {
            case note, error, caution
        }

        private let text: String
        private let tone: Tone

        public init(_ text: String, tone: Tone = .note) {
            self.text = text
            self.tone = tone
        }

        public var body: some View {
            Text(text).font(IOSDesign.footer).foregroundStyle(colour).fixedSize(horizontal: false, vertical: true)
                .iosRowKind(.caption)
        }

        private var colour: Color {
            switch tone {
            case .note: IOSDesign.textSecondary
            case .error: IOSDesign.error
            case .caution: IOSDesign.caution
            }
        }
    }

    /// Rows inside one card row (a group of fields that belong together, such as one server): each subview a grid row at
    /// least 44 pt tall with the card row's padding, with a hairline above every one but the first; a continuation row has
    /// no hairline and is pulled up a step (a second address box 4 pt under the first, buttons 6 pt under a field), and a
    /// caption has neither a hairline nor a minimum height (see ``IOSRowKind``).
    public struct IOSSubRows<Content: View>: View {
        private let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            Group(subviews: content) { rows in
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(rows) { row in
                        row.iosSubRow(
                            row.containerValues.iosRowKind, first: row.id == rows.first?.id, last: row.id == rows.last?.id,
                        )
                    }
                }
            }
        }
    }

    private extension View {
        /// One row of ``IOSSubRows``: the row padding (none above the first or a caption, a step less above a
        /// continuation, none below the last), the minimum height (none for a caption) and the hairline above a `row` that
        /// is not the first. The hairline runs on to the card's right edge, as the card's own row dividers do. A row keeps
        /// its own height: a stack proposed less height must not squeeze a row's padding away (rows of a List row would
        /// otherwise shrink to their minimum and overlap).
        func iosSubRow(_ kind: IOSRowKind, first: Bool, last: Bool) -> some View {
            frame(
                maxWidth: .infinity,
                minHeight: kind == .caption ? 0 : IOSDesignScale.minimumTouchHeight - 2 * IOSDesign.Space.rowVertical,
                alignment: .leading,
            )
            .padding(.top, first || kind == .caption ? 0 : kind.topPadding)
            .padding(.bottom, last ? 0 : IOSDesign.Space.rowVertical)
            .fixedSize(horizontal: false, vertical: true)
            .overlay(alignment: .top) {
                if !first, kind == .row {
                    Rectangle().fill(IOSDesign.hairline).frame(height: IOSDesign.Stroke.hairline)
                        .padding(.trailing, -IOSDesign.Space.rowHorizontal)
                }
            }
        }
    }

    /// The rows of one List section drawn as a card: each subview of `content` takes ``View/iosCardRow(_:selected:)`` at
    /// its position, without a hairline when it continues the row above (see ``IOSRowKind``). Rows whose content is empty
    /// take no place. For a ForEach with move or delete actions, set the positions by hand instead, so the List keeps those
    /// actions.
    public struct IOSListCardRows<Content: View>: View {
        private let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            Group(subviews: content) { rows in
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    row.iosCardRow(IOSCardRowPosition(index: index, count: rows.count), kind: row.containerValues.iosRowKind)
                }
            }
        }
    }
#endif
