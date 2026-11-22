// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI
    import UniformTypeIdentifiers

    /// Lists what the bundle holds, offers the log toggle, then exports. The save panel opens only after the daemon replied.
    package struct MacDiagnosticsExportSheet: View {
        @Environment(\.dismiss) private var dismiss
        @State private var export: MacDiagnosticsExport

        package init(model: MacShellModel) {
            _export = State(initialValue: MacDiagnosticsExport(
                operations: model.operations,
                chooseDestination: Self.askForDestination,
            ))
        }

        package var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                Text(MacStrings.exportDiagnostics).font(.title3.weight(.semibold))
                Text(MacStrings.theArchiveHoldsTheseRedactedItems)
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(MacStrings.diagnosticsContents, id: \.self) { Label($0, systemImage: "checkmark.circle") }
                }
                Toggle(MacStrings.includeLogs, isOn: $export.includeLogs)
                    .wgexControl(.settings, "includeDiagnosticsLogs", label: MacStrings.includeLogs)
                    .disabled(export.isWorking)
                if case let .failed(message) = export.phase {
                    Text(message).foregroundStyle(MacDesign.error).accessibilityIdentifier("wgex.settings.diagnosticsError")
                }
                if export.phase == .saved {
                    Text(MacStrings.diagnosticsSaved)
                }
                HStack {
                    Spacer()
                    Button(export.phase == .saved ? MacStrings.done : MacStrings.cancel) { dismiss() }
                        .wgexControl(.settings, "closeDiagnosticsSheet", label: MacStrings.cancel)
                        .keyboardShortcut(.cancelAction)
                    Button(MacStrings.exportEllipsis) { Task { await export.export() } }
                        .wgexControl(.settings, "exportDiagnostics", label: MacStrings.exportDiagnostics)
                        .buttonStyle(.macPrimary)
                        .keyboardShortcut(.defaultAction)
                        .disabled(export.isWorking || export.phase == .saved)
                }
            }
            .buttonStyle(.macSecondary)
            .padding(20).frame(width: 440)
            .background(MacDesign.pageBackground)
        }

        /// Non-modal: `begin` returns at once and the run loop keeps serving the main window while the panel is open.
        @MainActor private static func askForDestination(_ name: String) async -> URL? {
            let panel = NSSavePanel()
            panel.nameFieldStringValue = name
            panel.allowedContentTypes = [.zip]
            panel.canCreateDirectories = true
            return await withCheckedContinuation { continuation in
                panel.begin { continuation.resume(returning: $0 == .OK ? panel.url : nil) }
            }
        }
    }

    /// The "Export Diagnostics…" button with its sheet; the sheet never blocks the main window.
    package struct MacDiagnosticsExportButton: View {
        private let model: MacShellModel
        @State private var presented = false

        package init(model: MacShellModel) {
            self.model = model
        }

        package var body: some View {
            Button(MacStrings.exportDiagnosticsEllipsis) { presented = true }
                .wgexControl(.settings, "exportDiagnosticsOpen", label: MacStrings.exportDiagnostics)
                .sheet(isPresented: $presented) { MacDiagnosticsExportSheet(model: model) }
        }
    }
#endif
