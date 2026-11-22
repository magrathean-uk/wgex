// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore
import WGEXUI

@main
public struct WGEXiOSApp: App {
    @State private var model = AppModel()

    public init() {}

    public var body: some Scene {
        WindowGroup {
            IOSRootView(model: model)
                .preferredColorScheme(model.appearanceOverride)
                .task { await model.run() }
        }
    }
}

/// The shell is the shared iPhone and iPad window (SPEC 10); the app adds preference saving, Open In and the debug page.
private struct IOSRootView: View {
    @Bindable var model: AppModel

    var body: some View {
        IOSShellScreen(model: model) {
            #if DEBUG
                DebugHarnessScreen(model: model)
            #else
                EmptyView()
            #endif
        }
        .onChange(of: model.featureFlags) { _, _ in Task { await model.savePreferences() } }
        .onChange(of: model.preferenceSnapshot) { _, _ in Task { await model.savePreferences() } }
        .onOpenURL { url in
            // Open In, the share sheet and Files hand over a .conf or .zip; the shell shows its review.
            guard url.isFileURL else { return }
            model.importFile(at: url)
        }
    }
}
