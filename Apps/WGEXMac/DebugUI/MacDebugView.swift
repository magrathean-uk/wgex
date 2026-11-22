// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal

import SwiftUI
import WGEXUI

#if DEBUG
    import WGEXCore
    import WGEXTesting

    /// Always composes its own fakes, independently of the main app's launch arguments.
    public struct MacDebugView: View {
        public init() {}
        @State private var model = MacAppModel(arguments: ["-WGEXFakeBackend"])
        @State private var fixtureName = "Example · Mac"
        @State private var selectedState: ProtectionVerdict = .unprotected
        public var body: some View {
            NavigationStack {
                Form {
                    Section("DebugUI - fixture backend") {
                        Text("No service registration is performed by this window. All status changes are simulated.")
                        TextField("Fixture name", text: $fixtureName)
                        Button("Load fixture") { Task { await model.loadFixture(name: fixtureName) } }
                        Picker("Orb state", selection: $selectedState) {
                            ForEach(ProtectionVerdict.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        Button("Publish fixture state") { publish() }
                        Button("Simulate downgrade detected") { model.shell.reportDowngrade() }
                        Text("Service registration: \(model.shell.serviceState.rawValue)")
                        Text("Tunnel phase: \(String(describing: model.shell.status.phase))")
                        Text(model.shell.presentation.primary)
                        Button(model.shell.presentation.action.title) { Task { await model.shell.toggleConnection() } }
                            .buttonStyle(.glassProminent)
                        EventsTimeline(events: model.shell.status.recentEvents)
                    }
                }.formStyle(.grouped)
            }
            .frame(minWidth: 600, minHeight: 640)
            .task { await model.start() }
        }

        private func publish() {
            let generation = Generation(rawValue: 1)
            var status = TunnelStatus.idle
            switch selectedState {
            case .protected: status.phase = .active(generation); status.protection = .protected
            case .connecting: status.phase = .preparing(generation); status.protection = .blocked
            case .reasserting: status.phase = .reasserting(generation, reason: .wake); status.protection = .blocked
            case .blocked: status.phase = .failed(.timedOut, blockedByPolicy: true, needsSecrets: false); status.protection = .blocked
            case .captiveWindow:
                let expires = Date().addingTimeInterval(300)
                status.phase = .captiveWindow(generation, expires: expires); status.protection = .captiveWindow(expires: expires)
            case .unprotected: break
            // Inactive belongs to profile selection; it has no backend status to publish.
            case .inactive: return
            case .unsupported: status.protection = .unsupported
            case .unknown, .stale: status.protection = .unknown
            }
            model.shell.receive(status, at: selectedState == .stale ? Date().addingTimeInterval(-20) : Date())
            model.shell.tick(at: Date())
        }
    }

    public struct MacDebugWindowCommand: View {
        private let model: MacAppModel
        @Environment(\.openWindow) private var openWindow
        public init(model: MacAppModel) {
            self.model = model
        }

        public var body: some View {
            Button("Debug harness…") {
                model.showsDebug = true
                model.requestWindow(.reopen) { openWindow(id: "main") }
            }
        }
    }

    #Preview("1024 pt - chart and events toolbar") {
        let shell = MacShellModel(
            dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
            profiles: [TunnelProfile(name: "Preview")],
            status: .idle,
        )
        MacMainWindowView(model: shell).frame(width: 1024, height: 850)
    }
#endif

/// Debug is presented within the main window in development builds only.
internal struct MacDebugSheet: ViewModifier {
    internal let model: MacAppModel
    internal func body(content: Content) -> some View {
        #if DEBUG
            content.sheet(isPresented: Binding(get: { model.showsDebug }, set: { model.showsDebug = $0 })) {
                MacDebugView()
                    .toolbar { Button(MacStrings.done) { model.showsDebug = false } }
            }
        #else
            content
        #endif
    }
}
