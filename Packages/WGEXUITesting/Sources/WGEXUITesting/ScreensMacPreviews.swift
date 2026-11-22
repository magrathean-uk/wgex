// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    /// Complete scene/state matrix. All measurements are deterministic fixtures;
    /// no application, real controller or live service is constructed.
    public struct MacScreenPreview: View {
        public enum Screen {
            case menu, window, onboarding(MacOnboardingStep)
            case settings(MacSettingsTab), importSource, importReview(ImportReviewPreviewScenario), toast, empty
            /// A settings page inside the main window, with the sidebar.
            case windowSettings(MacSettingsTab)
            /// The Edit sheet on the fixture tunnel.
            case editSheet
            /// The Edit sheet with validation errors (MTU and endpoint) listed under the form.
            case editSheetErrors
            /// The Edit sheet in Edit as Text.
            case editSheetText
            /// The whole Edit sheet, tall enough for every group: on the fixture tunnel, and with long values.
            case editSheetFull, editSheetLong
        }

        private let screen: Screen
        @State private var model: MacShellModel
        @State private var review: ImportReviewModel?

        public init(
            _ screen: Screen, verdict: ProtectionVerdict = .protected,
            connection: MacDaemonConnectionState? = nil,
        ) {
            self.screen = screen
            let backend = FakeTunnelBackend()
            let service = FakeServiceController(initial: .enabled)
            let now = PreviewFixtures.referenceDate
            let status = Self.status(verdict, at: now)
            backend.publish(status)
            let profile = Self.profile()
            let profiles = [profile, TunnelProfile(name: "Cabin"), TunnelProfile(name: "Office"), TunnelProfile(name: "Lab")]
            var preferences = MacPreferences()
            preferences.flags.relayTransports = true
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: service, simulated: connection == nil,
                operations: MacShellOperations(secureInstall: { .verified }, refreshDaemon: { true }),
            ), profiles: profiles, preferences: preferences, status: status, now: now)
            model.receiveService(.enabled)
            if let connection {
                model.receiveConnection(connection)
            }
            if verdict != .unprotected, verdict != .connecting, verdict != .unknown {
                model.receive(Self.status(.protected, at: now), at: now)
                Self.measure(model, profile: profile, at: now)
                model.receive(status, at: now)
            }
            if verdict == .stale {
                model.tick(at: now.addingTimeInterval(120))
            }
            if verdict == .inactive {
                model.selectedProfileID = profiles[1].id
            }
            switch screen {
            case let .onboarding(step): model.revisit(step)
            case let .settings(tab): model.settingsTab = tab
            case let .windowSettings(tab): model.windowSelection = .settings(tab)
            case .empty: model.profiles = []; model.selectedProfileID = nil
            default: break
            }
            _model = State(initialValue: model)
        }

        private static func status(_ verdict: ProtectionVerdict, at now: Date) -> TunnelStatus {
            let generation = Generation(rawValue: 3)
            var status = TunnelStatus(
                phase: .active(generation),
                protection: .protected,
                transport: nil,
                health: .init(
                    level: .healthy,
                    lastHandshake: now.addingTimeInterval(-18),
                    rxRate: 1_250_000,
                    txRate: 160_000,
                ),
                recentEvents: PreviewFixtures.events,
            )
            switch verdict {
            case .protected, .stale: break
            case .connecting: status.phase = .preparing(generation); status.protection = .blocked
            case .reasserting: status.phase = .reasserting(generation, reason: .pathChanged); status.protection = .blocked
            case .blocked: status.phase = .failed(.timedOut, blockedByPolicy: true, needsSecrets: false); status.protection = .blocked
            case .captiveWindow:
                let expires = now.addingTimeInterval(272)
                status.phase = .captiveWindow(generation, expires: expires); status.protection = .captiveWindow(expires: expires)
            case .unprotected: status.phase = .idle; status.protection = .unprotected
            case .unsupported: status.protection = .unsupported
            case .inactive: break
            case .unknown: status.protection = .unknown
            }
            return status
        }

        private static func profile() -> TunnelProfile {
            var profile = PreviewFixtures.profile
            profile.name = "Home"
            if let data = try? FixtureLoader.repository().data("conf/ipv6-dual-stack.conf") {
                var bytes = Array(data)
                if let parsed = try? parseWgQuick(&bytes, name: "Home") {
                    profile = parsed.profile; profile.original = nil
                }
            }
            return profile
        }

        private static func measure(_ model: MacShellModel, profile: TunnelProfile, at now: Date) {
            for index in 0 ... 60 {
                model.receiveStatistics(TunnelStatistics(
                    generation: 3, sampledAt: now.addingTimeInterval(Double(index * 5 - 300)), interfaceName: "utun7",
                    listenPort: 51820,
                    peers: [PeerStatistics(
                        publicKey: profile.interface.publicKey,
                        endpoint: profile.peers.first?.endpoint,
                        lastHandshake: now.addingTimeInterval(-18),
                        rxBytes: UInt64(index * 750_000 + index * index * 10000),
                        txBytes: UInt64(index * 90000 + index * index * 1000),
                        persistentKeepalive: 25,
                    )],
                ))
            }
        }

        public var body: some View {
            Group {
                switch screen {
                case .menu: MacMenuBarView(model: model)
                case .window, .empty, .windowSettings: MacMainWindowView(model: model).frame(width: 1100, height: 860)
                case .editSheet: MacEditSheetPreview(.valid)
                case .editSheetErrors: MacEditSheetPreview(.errors)
                case .editSheetText: MacEditSheetPreview(.valid, opensAsText: true)
                case .editSheetFull: MacEditSheetPreview(.valid, height: MacEditSheetPreview.fullHeight)
                case .editSheetLong: MacEditSheetPreview(try? EditorLongValuesFixture.makeModel(), height: MacEditSheetPreview.fullHeight)
                case .onboarding: MacOnboardingView(model: model)
                case .settings: MacSettingsView(model: model)
                case .importSource: MacImportSheet()
                case .importReview: MacImportSheet(review: review)
                case .toast: MacToast("Secure install verified. Signature and launch constraints match.").padding(24)
                }
            }
            .environment(\.wgexDisplayDate, model.now)
            .task {
                await model.refreshService(); await model.verifySecureInstall()
                if case let .importReview(scenario) = screen {
                    review = try? scenario.makeModel()
                }
            }
        }
    }

    /// The Edit sheet on the dual-stack fixture.
    private struct MacEditSheetPreview: View {
        /// Tall enough to show every group of the sheet.
        static let fullHeight: CGFloat = 2600
        @State private var model: ProfileEditorModel?
        private let opensAsText: Bool
        private let height: CGFloat

        init(_ scenario: EditorPreviewScenario, opensAsText: Bool = false, height: CGFloat = 680) {
            self.init(try? scenario.makeModel(), opensAsText: opensAsText, height: height)
        }

        init(_ model: ProfileEditorModel?, opensAsText: Bool = false, height: CGFloat = 680) {
            _model = State(initialValue: model)
            self.opensAsText = opensAsText
            self.height = height
        }

        var body: some View {
            if let model {
                MacTunnelEditSheet(model: model, onSave: { _, _ in }, onCancel: {}, opensAsText: opensAsText, height: height)
            }
        }
    }

    #Preview("Mac window settings general, light") { MacScreenPreview(.windowSettings(.general)).preferredColorScheme(.light) }
    #Preview("Mac window settings protection, dark") { MacScreenPreview(.windowSettings(.protection)).preferredColorScheme(.dark) }
    #Preview("Mac edit sheet, light") { MacScreenPreview(.editSheet).preferredColorScheme(.light) }
    #Preview("Mac edit sheet, errors, dark") { MacScreenPreview(.editSheetErrors).preferredColorScheme(.dark) }
    #Preview("Mac edit sheet, Edit as Text, light") { MacScreenPreview(.editSheetText).preferredColorScheme(.light) }
    #Preview("Mac menu, protected, light") { MacScreenPreview(.menu, verdict: .protected).preferredColorScheme(.light) }
    #Preview("Mac menu, connecting, light") { MacScreenPreview(.menu, verdict: .connecting).preferredColorScheme(.light) }
    #Preview("Mac menu, reasserting, light") { MacScreenPreview(.menu, verdict: .reasserting).preferredColorScheme(.light) }
    #Preview("Mac menu, blocked, light") { MacScreenPreview(.menu, verdict: .blocked).preferredColorScheme(.light) }
    #Preview("Mac menu, captiveWindow, light") { MacScreenPreview(.menu, verdict: .captiveWindow).preferredColorScheme(.light) }
    #Preview("Mac menu, unprotected, light") { MacScreenPreview(.menu, verdict: .unprotected).preferredColorScheme(.light) }
    #Preview("Mac menu, unknown, light") { MacScreenPreview(.menu, verdict: .unknown).preferredColorScheme(.light) }
    #Preview("Mac menu, stale, light") { MacScreenPreview(.menu, verdict: .stale).preferredColorScheme(.light) }
    #Preview("Mac menu, unsupported, light") { MacScreenPreview(.menu, verdict: .unsupported).preferredColorScheme(.light) }
    #Preview("Mac window, protected, light") { MacScreenPreview(.window, verdict: .protected).preferredColorScheme(.light) }
    #Preview("Mac window, connecting, light") { MacScreenPreview(.window, verdict: .connecting).preferredColorScheme(.light) }
    #Preview("Mac window, reasserting, light") { MacScreenPreview(.window, verdict: .reasserting).preferredColorScheme(.light) }
    #Preview("Mac window, blocked, light") { MacScreenPreview(.window, verdict: .blocked).preferredColorScheme(.light) }
    #Preview("Mac window, captiveWindow, light") { MacScreenPreview(.window, verdict: .captiveWindow).preferredColorScheme(.light) }
    #Preview("Mac window, unprotected, light") { MacScreenPreview(.window, verdict: .unprotected).preferredColorScheme(.light) }
    #Preview("Mac window, unknown, light") { MacScreenPreview(.window, verdict: .unknown).preferredColorScheme(.light) }
    #Preview("Mac window, stale, light") { MacScreenPreview(.window, verdict: .stale).preferredColorScheme(.light) }
    #Preview("Mac window, unsupported, light") { MacScreenPreview(.window, verdict: .unsupported).preferredColorScheme(.light) }
    #Preview("Mac setup welcome, light") { MacScreenPreview(.onboarding(.welcome)).preferredColorScheme(.light) }
    #Preview("Mac setup backgroundService, running") {
        MacScreenPreview(.onboarding(.backgroundService), connection: .connected(daemonBuild: 42))
    }

    #Preview("Mac setup backgroundService, starting") {
        MacScreenPreview(.onboarding(.backgroundService), connection: .connecting)
    }

    #Preview("Mac setup backgroundService, light") { MacScreenPreview(.onboarding(.backgroundService)).preferredColorScheme(.light) }
    #Preview("Mac setup addTunnel, light") { MacScreenPreview(.onboarding(.addTunnel)).preferredColorScheme(.light) }
    #Preview("Mac settings general, light") { MacScreenPreview(.settings(.general)).preferredColorScheme(.light) }
    #Preview("Mac settings protection, light") { MacScreenPreview(.settings(.protection)).preferredColorScheme(.light) }
    #Preview("Mac settings network, light") { MacScreenPreview(.settings(.network)).preferredColorScheme(.light) }
    #Preview("Mac settings service, light") { MacScreenPreview(.settings(.service)).preferredColorScheme(.light) }
    #Preview("Mac settings diagnostics, light") { MacScreenPreview(.settings(.diagnostics)).preferredColorScheme(.light) }
    #Preview("Mac settings about, light") { MacScreenPreview(.settings(.about)).preferredColorScheme(.light) }
    #Preview("Mac empty, light") { MacScreenPreview(.empty).preferredColorScheme(.light) }
    #Preview("Mac toast, light") { MacScreenPreview(.toast).preferredColorScheme(.light) }
    #Preview("Mac importSource, light") { MacScreenPreview(.importSource).preferredColorScheme(.light) }
    #Preview("Mac import clean, light") { MacScreenPreview(.importReview(.clean)).preferredColorScheme(.light) }
    #Preview("Mac import errors, light") { MacScreenPreview(.importReview(.errors)).preferredColorScheme(.light) }
    #Preview("Mac import warnings, light") { MacScreenPreview(.importReview(.warnings)).preferredColorScheme(.light) }
    #Preview("Mac import duplicate, light") { MacScreenPreview(.importReview(.duplicate)).preferredColorScheme(.light) }
    #Preview("Mac import keyInUse, light") { MacScreenPreview(.importReview(.keyInUse)).preferredColorScheme(.light) }
    #Preview("Mac menu, protected, dark") { MacScreenPreview(.menu, verdict: .protected).preferredColorScheme(.dark) }
    #Preview("Mac menu, connecting, dark") { MacScreenPreview(.menu, verdict: .connecting).preferredColorScheme(.dark) }
    #Preview("Mac menu, reasserting, dark") { MacScreenPreview(.menu, verdict: .reasserting).preferredColorScheme(.dark) }
    #Preview("Mac menu, blocked, dark") { MacScreenPreview(.menu, verdict: .blocked).preferredColorScheme(.dark) }
    #Preview("Mac menu, captiveWindow, dark") { MacScreenPreview(.menu, verdict: .captiveWindow).preferredColorScheme(.dark) }
    #Preview("Mac menu, unprotected, dark") { MacScreenPreview(.menu, verdict: .unprotected).preferredColorScheme(.dark) }
    #Preview("Mac menu, unknown, dark") { MacScreenPreview(.menu, verdict: .unknown).preferredColorScheme(.dark) }
    #Preview("Mac menu, stale, dark") { MacScreenPreview(.menu, verdict: .stale).preferredColorScheme(.dark) }
    #Preview("Mac menu, unsupported, dark") { MacScreenPreview(.menu, verdict: .unsupported).preferredColorScheme(.dark) }
    #Preview("Mac window, protected, dark") { MacScreenPreview(.window, verdict: .protected).preferredColorScheme(.dark) }
    #Preview("Mac window, connecting, dark") { MacScreenPreview(.window, verdict: .connecting).preferredColorScheme(.dark) }
    #Preview("Mac window, reasserting, dark") { MacScreenPreview(.window, verdict: .reasserting).preferredColorScheme(.dark) }
    #Preview("Mac window, blocked, dark") { MacScreenPreview(.window, verdict: .blocked).preferredColorScheme(.dark) }
    #Preview("Mac window, captiveWindow, dark") { MacScreenPreview(.window, verdict: .captiveWindow).preferredColorScheme(.dark) }
    #Preview("Mac window, unprotected, dark") { MacScreenPreview(.window, verdict: .unprotected).preferredColorScheme(.dark) }
    #Preview("Mac window, unknown, dark") { MacScreenPreview(.window, verdict: .unknown).preferredColorScheme(.dark) }
    #Preview("Mac window, stale, dark") { MacScreenPreview(.window, verdict: .stale).preferredColorScheme(.dark) }
    #Preview("Mac window, unsupported, dark") { MacScreenPreview(.window, verdict: .unsupported).preferredColorScheme(.dark) }
    #Preview("Mac setup welcome, dark") { MacScreenPreview(.onboarding(.welcome)).preferredColorScheme(.dark) }
    #Preview("Mac setup backgroundService, dark") { MacScreenPreview(.onboarding(.backgroundService)).preferredColorScheme(.dark) }
    #Preview("Mac setup addTunnel, dark") { MacScreenPreview(.onboarding(.addTunnel)).preferredColorScheme(.dark) }
    #Preview("Mac settings general, dark") { MacScreenPreview(.settings(.general)).preferredColorScheme(.dark) }
    #Preview("Mac settings protection, dark") { MacScreenPreview(.settings(.protection)).preferredColorScheme(.dark) }
    #Preview("Mac settings network, dark") { MacScreenPreview(.settings(.network)).preferredColorScheme(.dark) }
    #Preview("Mac settings service, dark") { MacScreenPreview(.settings(.service)).preferredColorScheme(.dark) }
    #Preview("Mac settings diagnostics, dark") { MacScreenPreview(.settings(.diagnostics)).preferredColorScheme(.dark) }
    #Preview("Mac settings about, dark") { MacScreenPreview(.settings(.about)).preferredColorScheme(.dark) }
    #Preview("Mac empty, dark") { MacScreenPreview(.empty).preferredColorScheme(.dark) }
    #Preview("Mac toast, dark") { MacScreenPreview(.toast).preferredColorScheme(.dark) }
    #Preview("Mac importSource, dark") { MacScreenPreview(.importSource).preferredColorScheme(.dark) }
    #Preview("Mac import clean, dark") { MacScreenPreview(.importReview(.clean)).preferredColorScheme(.dark) }
    #Preview("Mac import errors, dark") { MacScreenPreview(.importReview(.errors)).preferredColorScheme(.dark) }
    #Preview("Mac import warnings, dark") { MacScreenPreview(.importReview(.warnings)).preferredColorScheme(.dark) }
    #Preview("Mac import duplicate, dark") { MacScreenPreview(.importReview(.duplicate)).preferredColorScheme(.dark) }
    #Preview("Mac import keyInUse, dark") { MacScreenPreview(.importReview(.keyInUse)).preferredColorScheme(.dark) }
#endif

#if os(macOS)
    #Preview("Mac window, inactive, light") { MacScreenPreview(.window, verdict: .inactive).previewTraits(.light) }
    #Preview("Mac window, inactive, dark") { MacScreenPreview(.window, verdict: .inactive).previewTraits(.dark) }
    #Preview("Mac window, accessibility text, light") { MacScreenPreview(.window).previewTraits(.accessibilityText) }
    #Preview("Mac window, accessibility text, dark") {
        MacScreenPreview(.window).previewTraits(PreviewTraits(id: "AX dark", dark: true, accessibilityText: true))
    }

    #Preview("Mac window, Reduce Motion, light") { MacScreenPreview(.window, verdict: .connecting).previewTraits(.reduceMotion) }
    #Preview("Mac window, Reduce Motion, dark") {
        MacScreenPreview(.window, verdict: .connecting).previewTraits(PreviewTraits(id: "Motion dark", dark: true, reduceMotion: true))
    }

    #Preview("Mac window, occluded") {
        MacScreenPreview(.window, verdict: .connecting)
            .environment(\.wgexSurfaceVisible, false).environment(\.wgexSurfaceAnimating, false)
    }
#endif
