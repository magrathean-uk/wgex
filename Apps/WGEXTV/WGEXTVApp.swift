// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import SwiftUI
import WGEXCore
import WGEXUI

@main
internal struct WGEXTVApp: App {
    @State private var model = TVAppModel()
    internal var body: some Scene {
        WindowGroup { TVRootView(model: model) }
    }
}

private struct TVRootView: View {
    @Bindable internal var model: TVAppModel
    @State private var route: AddRoute?
    @State private var pairing: TVPairingModel?
    @State private var tab = 0
    @State private var saveRevision = 0
    private enum AddRoute: String, Identifiable {
        case pairing, paste
        var id: String {
            rawValue
        }
    }

    internal var body: some View {
        Group {
            if !model.settings.privacyAccepted {
                TVFirstRunScreen(settings: $model.settings) { Task { await model.saveSettings() } }
            } else {
                TabView(selection: $tab) {
                    Tab("Connection", systemImage: "shield", value: 0) {
                        NavigationStack {
                            if model.profiles.isEmpty {
                                empty
                            } else {
                                TVConnectionScreen(
                                    name: model.selected?.name ?? "Choose a profile",
                                    status: model.status,
                                    settings: model.settings,
                                    flags: model.flags,
                                    sampledAt: model.sampledAt,
                                    busy: model.busy,
                                ) { action in
                                    Task {
                                        if action == .checkAgain {
                                            await model.refreshStatus()
                                        } else {
                                            await model.connect()
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Tab("Profiles", systemImage: "square.grid.2x2", value: 1) {
                        NavigationStack {
                            TVProfilesScreen(
                                profiles: model.profiles,
                                selectedID: model.selectedID,
                                status: model.status,
                                onConnect: { profile in Task { await model.connect(profile); tab = 0 } },
                                onEdit: { profile in Task { await model.openEditor(profile) } },
                                onDelete: { profile in Task { await model.delete(profile) } },
                                onPair: openPairing,
                                onPaste: { route = .paste },
                            )
                        }
                    }
                    Tab("Settings", systemImage: "gear", value: 2) {
                        NavigationStack {
                            TVSettingsScreen(settings: $model.settings, flags: $model.flags)
                                .disabled(model.busy)
                            #if DEBUG
                                .toolbar {
                                    NavigationLink("Debug harness") { TVDebugScreen(model: model) }
                                }
                            #endif
                        }
                    }
                }
            }
        }
        .task { await model.run() }
        .onChange(of: model.settings) { _, _ in Task { await model.saveSettings() } }
        .onChange(of: model.flags) { _, _ in Task { await model.saveSettings() } }
        .sheet(item: $route, onDismiss: { model.paste.clear() }) { value in
            NavigationStack {
                Group {
                    if value == .pairing, let pairing {
                        TVPairingScreen(model: pairing)
                    } else {
                        TVPasteImportScreen(model: model.paste, existing: model.profiles) { profile, keys, connect in
                            try model.stageImport(profile, keys: keys, connect: connect)
                            saveRevision += 1
                        }
                    }
                }
                .task(id: saveRevision) {
                    if await model.finishStagedImport() {
                        route = nil; tab = 0
                    }
                }
                .toolbar { Button("Done") { route = nil } }
            }
        }
        .sheet(isPresented: Binding(get: { model.editor != nil }, set: {
            if !$0 {
                model.editor = nil
            }
        })) {
            NavigationStack {
                if let editor = model.editor {
                    ProfileEditorForm(model: editor, onSave: { profile, keys in
                        try model.stageImport(profile, keys: keys, connect: false, applyDefaults: false)
                        saveRevision += 1
                    }, onCancel: { model.editor = nil })
                        .focusSection()
                        .task(id: saveRevision) { _ = await model.finishStagedImport() }
                }
            }
        }
        .overlay(alignment: .bottom) {
            VStack {
                Text("Preview backend. No VPN configuration is installed.").font(.footnote)
                if let message = model.message {
                    Text(message).accessibilityIdentifier("tv.operationMessage")
                }
            }.padding().background(.regularMaterial)
        }
    }

    private var empty: some View {
        TVEmptyProfilesScreen(onPair: openPairing, onPaste: { route = .paste })
    }

    private func openPairing() {
        if model.usesTemporaryStore {
            pairing = TVPairingModel(receiver: TVFakePairingReceiver(value: TVPairingSnapshot(
                payload: "wgex-pair://v1/00000000-0000-0000-0000-000000000001/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )))
        } else {
            pairing = TVPairingModel(receiver: TVPairingAdapter(app: model))
        }
        route = .pairing
    }
}
