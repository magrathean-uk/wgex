// SPDX-License-Identifier: MIT

import AppKit
import SwiftUI
import WGEXCore
import WGEXUI

@main
public struct WGEXMacApp: App {
    @State private var model: MacAppModel
    @NSApplicationDelegateAdaptor(MacApplicationDelegate.self) private var applicationDelegate

    public init() {
        let model = MacAppModel()
        _model = State(initialValue: model)
        applicationDelegate.activation = MacAppActivationCoordinator(
            isActive: { NSApplication.shared.isActive },
            activation: { loginLaunch in
                await model.start()
                await model.applicationActivated()
                if loginLaunch {
                    await model.shell.connectAtLogin()
                }
            },
        )
        applicationDelegate.launch = { model.willFinishLaunching(event: $0) }
        applicationDelegate.finishLaunch = { model.didFinishLaunching(event: $0) }
        applicationDelegate.reopen = { model.reopenRequested(hasVisibleWindows: $0) }
        applicationDelegate.statusItem = MacStatusItemController(model: model)
        applicationDelegate.flush = { await model.uiWork?.flushPreferences() }
    }

    public var body: some Scene {
        applicationScenes.commands {
            CommandGroup(replacing: .appInfo) {
                MacAppCommands(model: model, kind: .about)
            }
            CommandGroup(replacing: .appSettings) {
                MacAppCommands(model: model, kind: .settings)
                MacAppCommands(model: model, kind: .setup)
            }
            CommandGroup(replacing: .newItem) {
                Button(MacStrings.createEmptyTunnel, action: model.openNewProfile)
                    .keyboardShortcut("n")
                MacAppCommands(model: model, kind: .importTunnel)
                MacAppCommands(model: model, kind: .exportAll)
            }
            CommandMenu(MacStrings.tunnelMenu) {
                Button(model.shell.designPresentation.action.title) { Task { await model.shell.toggleActiveConnection() } }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(!model.shell.canToggleActiveConnection)
                    .wgexControl(.main, "connectionCommand", label: model.shell.designPresentation.action.title)
            }
            CommandGroup(replacing: .appTermination) {
                Button(MacStrings.quitWGEX) { model.shell.quit { NSApplication.shared.terminate(nil) } }
                    .keyboardShortcut("q").help(MacStrings.quittingDoesNotDisconnectTheTunnel)
                    .wgexControl(.main, "quitCommand", label: MacStrings.quitWGEX)
            }
            #if DEBUG
                CommandMenu("Debug") { MacDebugWindowCommand(model: model) }
            #endif
        }
    }

    @SceneBuilder private var applicationScenes: some Scene {
        Window(MacStrings.appName, id: "main") {
            MacMainScene(model: model)
        }
        .defaultLaunchBehavior(.suppressed)
        // A window open at logout is never brought back at login; the launch decision alone opens it.
        .restorationBehavior(.disabled)
        .defaultSize(width: 1100, height: 860)
    }
}

private struct MacMainScene: View {
    @Bindable private var model: MacAppModel
    init(model: MacAppModel) {
        self.model = model
    }

    var body: some View {
        MacMainWindowView(
            model: model.shell,
            edit: model.openEditor,
            export: model.openExport,
            exportAll: model.requestExportAll,
            addProfile: { model.routeWindow(.importTunnel); model.openImport() },
            paste: { model.routeWindow(.importTunnel); model.pasteImport() },
            acknowledgements: model.acknowledgements,
            revisit: { _ in model.shell.showsOnboarding = true },
            simulateApproval: model.simulateApproval,
        )
        .sheet(
            isPresented: $model.importing,
            onDismiss: model.importSheetDismissed,
        ) {
            MacImportScene(model: model)
        }
        .environment(\.macImportFromFile, MacWindowAction { [model] in
            model.routeWindow(.importTunnel); model.chooseImportFile()
        })
        .background {
            MacCancelShortcut(model: model)
        }
        .confirmationDialog(
            MacStrings.exportAllTitle, isPresented: $model.exportAllConfirming, titleVisibility: .visible,
        ) {
            Button(MacStrings.exportAllWithKeys, action: model.confirmExportAll)
                .wgexControl(.export, "confirmAll", label: MacStrings.exportAllWithKeys)
            Button(UserStrings.cancel, role: .cancel, action: model.cancelExportAll)
        } message: {
            Text(MacStrings.exportAllWarning)
        }
        .alert(MacStrings.export, isPresented: Binding(
            get: { model.exportAllMessage != nil },
            set: { shown in
                if !shown {
                    model.exportAllMessage = nil
                }
            },
        )) {
            Button(MacStrings.done) { model.exportAllMessage = nil }
        } message: {
            Text(model.exportAllMessage ?? "")
        }
        .macStatusTime(model.shell)
        .macSurfaceActivity { model.uiWork?.visibility($0, surface: "main") }
        .onChange(of: model.shell.preferences.hideDockIcon) { model.applyDock() }
        .dropDestination(for: URL.self) { urls, _ in
            model.routeWindow(.importTunnel)
            model.importURLs(urls)
            return !urls.isEmpty
        }
        .onOpenURL { model.routeWindow(.importTunnel); model.importURLs([$0]) }
        .task {
            await model.start()
            model.presentInitialOnboarding()
        }
        .sheet(
            isPresented: Binding(get: { model.shell.showsOnboarding }, set: { model.shell.showsOnboarding = $0 }),
            onDismiss: model.setupSheetDismissed,
        ) {
            MacOnboardingSheet(model: model)
        }
        .modifier(MacDebugSheet(model: model))
        .sheet(isPresented: Binding(get: { model.editor != nil }, set: {
            if !$0 {
                model.closeEditor()
            }
        })) {
            MacEditorScene(model: model)
        }
        .sheet(isPresented: Binding(get: { model.exportModel != nil }, set: {
            if !$0 {
                model.closeExport()
            }
        })) {
            if let export = model.exportModel {
                NavigationStack { ExportSheet(model: export) }
                    .frame(width: 520, height: 460)
                    .toolbar { Button(MacStrings.done, action: model.closeExport).wgexControl(
                        .export,
                        "closeSheet",
                        label: MacStrings.done,
                    )
                    }
            }
        }
    }
}

/// Setup (SPEC 7) on the main window. Step 3's rows and a dropped file close setup; the window then runs them.
private struct MacOnboardingSheet: View {
    let model: MacAppModel
    var body: some View {
        MacOnboardingView(model: model.shell, finished: {
            model.shell.showsOnboarding = false
            model.shell.routeWindow(.manageTunnels)
        }, addProfile: {
            model.leaveSetup(then: .chooseFile)
        }, paste: {
            model.leaveSetup(then: .paste)
        }, createEmpty: {
            model.leaveSetup(then: .createEmpty)
        }, dropProfiles: { urls in
            model.leaveSetup(then: .drop(urls)); return !urls.isEmpty
        }, simulateApproval: model.simulateApproval)
            .macSurfaceActivity { model.uiWork?.visibility($0, surface: "onboarding") }
            .task { await model.start() }
    }
}

private struct MacImportScene: View {
    @Bindable var model: MacAppModel
    var body: some View {
        MacImportSheet(
            reviews: model.importReviews,
            chooseFile: { model.chooseImportFile() }, paste: model.pasteImport,
            createEmpty: model.createEmptyTunnel, cancel: model.cancelImport,
            dropProfiles: { urls in model.importURLs(urls); return !urls.isEmpty }, saving: model.importSaving,
            errorMessage: model.importErrorMessage,
            confirm: { profile, secrets, connect, replacing in
                _ = try model.confirmImport(profile, secrets: secrets, connect: connect, replacing: replacing)
            },
            confirmAll: { _ = model.confirmAllImports(only: $0) },
        )
    }
}

/// The Edit sheet (SPEC 6.3) for the editor the app model holds; the main window hosts it.
private struct MacEditorScene: View {
    let model: MacAppModel
    var body: some View {
        if let editor = model.editor {
            MacTunnelEditSheet(
                model: editor,
                onSave: model.saveEditor,
                onCancel: model.closeEditor,
                errorCopy: { MacAppErrorCopy.resolve($0).message },
                connectedNetwork: { await model.connectedNetwork() },
            )
        }
    }
}

private struct MacAppCommands: View {
    enum Kind { case about, settings, setup, importTunnel, exportAll }
    let model: MacAppModel
    let kind: Kind
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        // Command views are built with the main menu before did-finish-launching, so this live environment action
        // is what the status item and the launch decision use; the App struct's own environment is never read.
        let _ = model.installWindowOpener { [openWindow] in
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
        switch kind {
        case .about:
            Button(MacStrings.aboutWGEX) { show(.about) }
                .wgexControl(.main, "about", label: MacStrings.aboutWGEX)
        case .settings:
            Button(MacStrings.settingsCommand) { show(.settings) }
                .keyboardShortcut(",")
        case .setup:
            Button(MacStrings.setupCommand) { show(.setup) }
                .wgexControl(.main, "setup", label: MacStrings.setupCommand)
        case .importTunnel:
            // SPEC 6.1: the menu goes straight to the file picker; what it returns opens Review Tunnel in the window.
            Button(MacStrings.importTunnelsFromFile) {
                show(.importTunnel); model.chooseImportFile()
            }
            .keyboardShortcut("i")
            .wgexControl(.main, "importCommand", label: MacStrings.importTunnelsFromFile)
        case .exportAll:
            Button(MacStrings.exportAllTunnels) { model.requestExportAll(); show(.manageTunnels) }
                .disabled(model.shell.profiles.isEmpty || model.exportAllRunning)
                .wgexControl(.main, "exportAllCommand", label: MacStrings.exportAllTunnels)
        }
    }

    private func show(_ entry: MacWindowEntryPoint) {
        model.requestWindow(entry) { openWindow(id: "main") }
    }
}

/// Only the key main window without a sheet registers the connection-cancel shortcut.
private struct MacCancelShortcut: View {
    let model: MacAppModel
    @Environment(\.wgexSurfaceAnimating) private var isKey

    var body: some View {
        if isKey, !model.shell.showsOnboarding, !model.importing, model.editor == nil, model.exportModel == nil,
           model.shell.designPresentation.action == .cancel
        {
            Button(UserStrings.cancel) { Task { await model.shell.toggleActiveConnection() } }
                .keyboardShortcut(".", modifiers: .command)
                .wgexControl(.main, "cancel", label: UserStrings.cancel)
                .hidden()
        }
    }
}
