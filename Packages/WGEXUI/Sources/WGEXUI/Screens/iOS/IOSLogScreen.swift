// SPDX-License-Identifier: MIT

#if os(iOS)
    import CoreTransferable
    import Foundation
    import SwiftUI
    import UniformTypeIdentifiers
    import WGEXCore

    /// Log (SPEC 8.4 carried to iOS): Events (time, category, sentence) or Raw (the app and extension log), newest at the
    /// bottom and kept scrolled there. Save Log… shares what the shown tab shows.
    public struct IOSLogScreen<Model: IOSAppState>: View {
        private let model: Model
        @State private var showsRaw = false
        @Environment(\.dynamicTypeSize) private var typeSize

        public init(model: Model) {
            self.model = model
        }

        private var lines: [TunnelEventLines.Line] {
            TunnelEventLines.lines(model.status.recentEvents)
        }

        public var body: some View {
            ScrollViewReader { proxy in
                List {
                    Section { logRows }
                    Section {} footer: {
                        Text(PlatformStrings.logFooterIOS)
                            .font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                            .iosListHeader()
                            .id("latest")
                    }
                }
                .iosCardList()
                .onChange(of: model.logText, initial: true) { _, _ in proxy.scrollTo("latest", anchor: .bottom) }
                .onChange(of: model.status.recentEvents) { _, _ in proxy.scrollTo("latest", anchor: .bottom) }
                .onChange(of: showsRaw) { _, _ in proxy.scrollTo("latest", anchor: .bottom) }
            }
            .navigationTitle(MacStrings.rawLog)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Picker(MacStrings.eventsFormat, selection: $showsRaw) {
                        Text(MacStrings.logEvents).tag(false)
                        Text(MacStrings.logRaw).tag(true)
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                    .accessibilityIdentifier("wgex.log.format")
                }
                ToolbarItem(placement: .primaryAction) { saveLogButton }
            }
            .task { await model.watchLog() }
        }
    }

    extension IOSLogScreen {
        /// The log card: one row of raw text, one placeholder row, or one row per event.
        @ViewBuilder private var logRows: some View {
            if showsRaw {
                if model.logText.isEmpty {
                    placeholderRow(MacStrings.noLogLinesYet)
                } else {
                    Text(model.logText)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(IOSDesign.text)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("wgex.log.raw")
                        .iosCardRow(.only)
                }
            } else if lines.isEmpty {
                placeholderRow(MacStrings.noEventsSinceWGEXStarted)
            } else {
                let rows = lines
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, line in
                    eventRow(line).iosCardRow(IOSCardRowPosition(index: index, count: rows.count))
                }
            }
        }

        private func placeholderRow(_ text: String) -> some View {
            Text(text).foregroundStyle(IOSDesign.textSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .iosCardRow(.only)
        }

        /// Save Log… in the navigation bar, always in reach; it shares what the shown tab shows and takes the window's
        /// accent tint.
        @ViewBuilder private var saveLogButton: some View {
            if showsRaw {
                ShareLink(item: IOSLogExport(read: { model.exportLog() }), preview: SharePreview("WGEX Log")) {
                    Label(MacStrings.saveLog, systemImage: "square.and.arrow.up")
                }
            } else {
                ShareLink(item: TunnelEventLines.text(lines), preview: SharePreview("WGEX Events")) {
                    Label(MacStrings.saveLog, systemImage: "square.and.arrow.up")
                }
            }
        }

        /// Time, then category and sentence beside it; at accessibility text sizes the time goes above them, so the
        /// sentence keeps the row's width.
        @ViewBuilder private func eventRow(_ line: TunnelEventLines.Line) -> some View {
            let time = Text(line.date, format: .dateTime.hour().minute().second())
                .monospacedDigit().foregroundStyle(IOSDesign.textSecondary)
            let words = VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                Text(line.category).font(IOSDesign.footer).foregroundStyle(IOSDesign.accent)
                Text(line.sentence).foregroundStyle(IOSDesign.text)
            }
            Group {
                if typeSize.isAccessibilitySize {
                    VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                        time
                        words
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    HStack(alignment: .firstTextBaseline, spacing: IOSDesign.Space.medium) {
                        time.lineLimit(1).layoutPriority(1)
                        words.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .textSelection(.enabled)
            .accessibilityElement(children: .combine)
        }
    }

    /// A named plain-text attachment lets the system share sheet offer Save to Files as well as other destinations.
    private nonisolated struct IOSLogExport: Transferable {
        let read: @MainActor @Sendable () -> Data

        static var transferRepresentation: some TransferRepresentation {
            DataRepresentation(exportedContentType: .plainText) { await $0.read() }
                .suggestedFileName("WGEX-log.txt")
        }
    }
#endif
