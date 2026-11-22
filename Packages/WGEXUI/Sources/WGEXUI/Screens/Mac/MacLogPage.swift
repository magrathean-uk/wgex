// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI
    import UniformTypeIdentifiers
    import WGEXCore

    /// Log (SPEC 8.4, E6): fills its page. Events lists every held event, oldest first; Raw shows the background service
    /// log, read only while Raw is shown. The tab switch, Save Log… and Export Diagnostics… sit on the title line.
    package struct MacLogPage: View {
        private let model: MacShellModel
        @State private var showsRaw = false
        @State private var log: MacActivityLog

        /// Time between log reads while Raw is shown.
        package static let logRefreshInterval: Duration = .seconds(1)

        package init(model: MacShellModel) {
            self.model = model
            _log = State(initialValue: MacActivityLog(read: model.operations.readLog))
        }

        private var lines: [MacAppPagesPresentation.EventLine] {
            MacAppPagesPresentation.eventLines(model.status.recentEvents)
        }

        private var shownIsEmpty: Bool {
            showsRaw ? log.buffer.entries.isEmpty : lines.isEmpty
        }

        package var body: some View {
            VStack(alignment: .leading, spacing: MacDesign.Space.groupGap) {
                MacPageTitle(MacSettingsTab.diagnostics.title)
                Group {
                    if showsRaw {
                        rawBody
                    } else {
                        eventsBody
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .macCard(padding: 0)
                Text(MacStrings.logFooter)
                    .font(MacDesign.caption).foregroundStyle(MacDesign.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 4)
            }
            .padding(MacDesign.Space.page)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(MacDesign.pageBackground)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Picker(MacStrings.eventsFormat, selection: $showsRaw) {
                        Text(MacStrings.logEvents).lineLimit(1).tag(false)
                        Text(MacStrings.logRaw).lineLimit(1).tag(true)
                    }
                    .pickerStyle(.segmented).labelsHidden().fixedSize()
                    .wgexControl(.events, "logView", label: MacStrings.eventsFormat)
                    Button(MacStrings.saveLog, action: saveLog)
                        .buttonStyle(.macSecondary)
                        .wgexControl(.events, "saveLog", label: MacStrings.saveLog)
                        .disabled(shownIsEmpty)
                        .lineLimit(1).fixedSize()
                    MacDiagnosticsExportButton(model: model)
                        .buttonStyle(.macSecondary)
                        .lineLimit(1).fixedSize()
                }
                .sharedBackgroundVisibility(.hidden)
            }
            // Reads only while Raw is shown; leaving the page or the tab cancels the loop.
            .task(id: showsRaw) {
                guard showsRaw else { return }
                while !Task.isCancelled {
                    await log.refresh()
                    try? await Task.sleep(for: Self.logRefreshInterval)
                }
            }
        }

        @ViewBuilder private var eventsBody: some View {
            if lines.isEmpty {
                emptyLine(MacStrings.noEventsSinceWGEXStarted)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(lines) { line in eventRow(line).id(line.id) }
                        }
                        .padding(.vertical, 6)
                    }
                    .defaultScrollAnchor(.bottom)
                    .onAppear { scrollToEnd(proxy, lines.last?.id) }
                    .onChange(of: model.status.recentEvents) { scrollToEnd(proxy, lines.last?.id) }
                }
            }
        }

        private func eventRow(_ line: MacAppPagesPresentation.EventLine) -> some View {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(line.date, format: .dateTime.hour().minute().second())
                    .monospacedDigit().foregroundStyle(MacDesign.textSecondary)
                    .lineLimit(1).fixedSize()
                Text(line.category).fontWeight(.medium).foregroundStyle(MacDesign.accent)
                    .lineLimit(1).frame(width: 84, alignment: .leading)
                Text(line.sentence).foregroundStyle(MacDesign.text).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 0)
            }
            .font(MacDesign.body)
            .padding(.horizontal, MacDesign.Space.rowHorizontal).padding(.vertical, 3)
            .textSelection(.enabled)
            .accessibilityElement(children: .combine)
            .wgexAX(.events, "event", label: line.sentence, item: String(line.date.timeIntervalSince1970))
        }

        @ViewBuilder private var rawBody: some View {
            if !log.available, log.buffer.entries.isEmpty {
                emptyLine(MacStrings.rawLogsAreNotAvailableFromThis)
            } else if log.buffer.entries.isEmpty {
                emptyLine(MacStrings.noLogLinesYet)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(log.buffer.entries) { entry in
                                Text(MacLogBuffer.render(entry.line))
                                    .font(.system(.caption, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(entry.id)
                            }
                        }
                        .textSelection(.enabled)
                        .padding(.horizontal, MacDesign.Space.rowHorizontal).padding(.vertical, 6)
                    }
                    .defaultScrollAnchor(.bottom)
                    .onAppear { scrollToEnd(proxy, log.buffer.entries.last?.id) }
                    .onChange(of: log.buffer.entries.last?.id) { scrollToEnd(proxy, log.buffer.entries.last?.id) }
                }
                .wgexAX(.events, "log", label: MacStrings.rawLog)
            }
        }

        private func emptyLine(_ text: String) -> some View {
            Text(text).foregroundStyle(MacDesign.textSecondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(MacDesign.Space.rowHorizontal)
        }

        private func scrollToEnd(_ proxy: ScrollViewProxy, _ last: some Hashable?) {
            if let last {
                proxy.scrollTo(last, anchor: .bottom)
            }
        }

        /// Asks for a .txt destination and writes what the shown tab shows only there.
        private func saveLog() {
            let text = showsRaw ? log.buffer.text : MacAppPagesPresentation.eventsText(lines)
            let panel = NSSavePanel()
            panel.nameFieldStringValue = MacLogFile.suggestedName(at: Date())
            panel.allowedContentTypes = [.plainText]
            panel.canCreateDirectories = true
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do { try MacAppPagesPresentation.saveLog(text, to: url) }
            catch { model.operationMessage = MacStrings.theLogCouldNotBeSaved }
        }
    }
#endif
