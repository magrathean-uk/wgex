// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if DEBUG
    import SwiftUI
    import WGEXUI

    /// iOS-only simulator harness. No NetworkExtension operations are exposed.
    internal struct DebugHarnessScreen: View {
        internal let model: AppModel
        @State private var configuration = ""
        @Environment(\.scenePhase) private var scenePhase

        internal var body: some View {
            Form {
                Section("Configuration") {
                    TextEditor(text: $configuration).frame(minHeight: 120).privacySensitive()
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                    Button("Load fixture") {
                        model.prepareFixture()
                        configuration = ""
                    }
                    Button("Parse") { model.prepareImport(configuration); configuration = "" }
                    EditorDiagnosticsView(model.importDiagnostics)
                    if model.review != nil {
                        Button("Store reviewed fixture") { Task { await model.confirmImport() } }
                            .disabled(model.review?.canImport != true || model.isBusy)
                    }
                }
                Section("Backend") {
                    Text(model.backendMessage)
                    Button("Connect / disconnect") { Task { await model.toggleConnection() } }
                        .disabled(!model.usesFakeBackend || model.selectedProfileID == nil || model.isBusy)
                }
                Section("Status stream") {
                    Text(model.presentation.accessibilityLabel).accessibilityIdentifier("wgex.debugStatus")
                    ForEach(Array(model.statusHistory.enumerated()), id: \.offset) { _, state in Text(state) }
                }
                if let message = model.operationMessage {
                    Text(message)
                }
            }
            .navigationTitle("Debug harness")
            .onChange(of: scenePhase) {
                _, phase in if phase != .active {
                    configuration = ""
                }
            }
            .onDisappear { configuration = "" }
        }
    }
#endif
