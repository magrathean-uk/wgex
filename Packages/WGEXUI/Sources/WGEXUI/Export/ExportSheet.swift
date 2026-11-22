// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore
#if os(macOS)
    import AppKit
    import UniformTypeIdentifiers
#elseif os(iOS)
    import UniformTypeIdentifiers
#endif

/// Only placeholder text reaches ShareLink. Keys require a separate confirmation sheet.
public struct ExportSheet: View {
    @Bindable private var model: ExportModel
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dismiss) private var dismiss
    @State private var showsConfirmation = false
    @State private var qrView: QRCodeView?
    @State private var failed = false
    @State private var confirmedPurpose: ExportModel.Purpose?
    #if os(iOS)
        @State private var document: ConfigurationFile?
        @State private var showsFileExporter = false
    #endif

    public init(model: ExportModel) {
        self.model = model
    }

    public var body: some View {
        Form {
            Section {
                #if !os(tvOS)
                    ShareLink(EditorStrings.share, item: model.shareableText)
                        .wgexControl(.export, "share", label: EditorStrings.share)
                    Button(EditorStrings.exportFile) { request(.file) }.wgexControl(.export, "exportFile", label: EditorStrings.exportFile)
                    Button(EditorStrings.qr) { request(.qr) }.wgexControl(.export, "qr", label: EditorStrings.qr)
                #else
                    Text(EditorStrings.qrUnavailable)
                #endif
            }
            if let qrView {
                Section(EditorStrings.qr) { Text(EditorStrings.qrWarning); qrView }
            }
            if failed {
                Section { Text(EditorStrings.exportFailed) }
            }
        }
        .navigationTitle(EditorStrings.export)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(EditorStrings.done) { clear(); dismiss() }.wgexControl(.export, "done", label: EditorStrings.done)
                    .buttonStyle(.glass)
            }
        }
        .sheet(isPresented: $showsConfirmation, onDismiss: exportAfterDismissal) { confirmation }
        .onDisappear { clear() }
        .onChange(of: scenePhase) {
            _, phase in if phase != .active {
                qrView = nil; confirmedPurpose = nil; model.cancel()
            }
        }
        #if os(iOS)
        .fileExporter(
            isPresented: $showsFileExporter,
            document: document,
            contentType: .data,
            defaultFilename: model.suggestedFilename,
        ) { result in
            document = nil
            if case .failure = result {
                failed = true
            }
        }
        .onChange(of: showsFileExporter) {
            _, showing in if !showing {
                document = nil
            }
        }
        #endif
    }

    private var confirmation: some View {
        NavigationStack {
            Form {
                Text(model.pendingPurpose == .qr ? EditorStrings.qrWarning : EditorStrings.exportWarning)
                Button(model.pendingPurpose == .qr ? EditorStrings.qr : EditorStrings.confirm) { confirm() }
                    .wgexControl(.export, "confirm", label: model.pendingPurpose == .qr ? EditorStrings.qr : EditorStrings.confirm)
                    .buttonStyle(.glassProminent)
                Button(EditorStrings.cancel, role: .cancel) { model.cancel(); showsConfirmation = false }.wgexControl(
                    .export,
                    "cancel",
                    label: EditorStrings
                        .cancel,
                )
            }
            .navigationTitle(EditorStrings.confirmExport)
        }
    }

    private func request(_ purpose: ExportModel.Purpose) {
        model.request(purpose); showsConfirmation = true
    }

    private func confirm() {
        confirmedPurpose = model.pendingPurpose
        model.confirm(); showsConfirmation = false
    }

    private func exportAfterDismissal() {
        guard let purpose = confirmedPurpose else { model.cancel(); return }
        confirmedPurpose = nil
        do {
            if purpose == .qr {
                qrView = try QRCodeView(payload: model.confirmedQRPayload())
            } else {
                #if os(macOS)
                    let panel = NSSavePanel()
                    panel.nameFieldStringValue = model.suggestedFilename
                    panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .data]
                    guard panel.runModal() == .OK, let url = panel.url else { model.cancel(); return }
                    try model.writeConfirmedFile(to: url)
                #elseif os(iOS)
                    document = try ConfigurationFile(model.confirmedFileText()); showsFileExporter = true
                #endif
            }
            failed = false
        } catch { failed = true }
    }

    private func clear() {
        qrView = nil; confirmedPurpose = nil; model.cancel()
        #if os(iOS)
            document = nil
        #endif
    }
}
