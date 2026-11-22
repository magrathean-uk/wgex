// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if DEBUG
    import Foundation
    import SwiftUI
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    internal struct TVDebugScreen: View {
        @Bindable internal var model: TVAppModel
        @State private var saveRevision = 0
        internal var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Text("Debug harness").font(.largeTitle)
                    Text("FakeTunnelBackend. No VPN configuration is installed.")
                    Button("Load fixture") { do { try model.paste.prepare(
                        bytes: GeneratedFixture.configurationBytes(),
                        existing: model.profiles,
                    ) } catch { model.paste.clear() }
                    }
                    TVPasteImportScreen(model: model.paste, existing: model.profiles) { profile, keys, connect in
                        try model.stageImport(profile, keys: keys, connect: connect); saveRevision += 1
                    }
                    Text("Status stream: \(TVConnectionState.presentation(model.status).primary)")
                    EventsTimeline(events: TVConnectionState.events(model.status.recentEvents))
                    Button(TVConnectionState.isRunning(model.status.phase) ? "Disconnect" : "Connect") {
                        Task { await model.connect() }
                    }.disabled(model.selected == nil || model.busy)
                }.padding(40).focusSection()
            }
            .task(id: saveRevision) { _ = await model.finishStagedImport() }
        }
    }
#endif
