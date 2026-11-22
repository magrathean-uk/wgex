// SPDX-License-Identifier: MIT

#if os(iOS)
    import Foundation
    import Observation
    import SwiftUI
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    /// A fixture ``IOSAppState`` for previews and picture tests: four tunnels, Home active with a live sample, recent
    /// events and a raw log. Nothing reaches a backend, storage, the camera or the network; actions change only this state.
    @MainActor @Observable
    public final class IOSPreviewModel: IOSAppState {
        public var profiles: [TunnelProfile]
        public var selectedProfileID: UUID?
        public var status: TunnelStatus
        public var featureFlags: FeatureFlags = .defaults
        public var protection = ProtectionPolicy(ipv6Policy: .tunnel)
        public var automaticFailover = true
        public var notifications = true
        public var onboardingComplete: Bool
        public var backendMessage = ""
        public var operationMessage: String?
        public var isBusy = false
        public var userInitiated = true
        public var pendingReviews: [ImportReviewModel] = []
        public var importDiagnostics: [ConfigDiagnostic] = []
        public var editor: ProfileEditorModel?
        public var activeProfileID: UUID?
        public var applyingProfileID: UUID?
        public var statistics: TunnelStatistics?
        public var statisticsProfileID: UUID?
        public var connectedNetwork: (() async -> ConnectedNetworkReading)?
        public var logText: String
        public let engineVersion = "b3bc704ef0ee"

        public var review: ImportReviewModel? {
            pendingReviews.first
        }

        public var pendingReviewCount: Int {
            pendingReviews.count
        }

        /// `active` starts Home with a live sample; otherwise every tunnel is off. `onboarded` false shows setup first.
        public init(active: Bool = true, onboarded: Bool = true, now: Date = Date()) {
            let home = Self.home()
            profiles = [home, TunnelProfile(name: "Cabin"), TunnelProfile(name: "Office"), TunnelProfile(name: "Lab")]
            selectedProfileID = home.id
            onboardingComplete = onboarded
            logText = Self.log
            guard active else {
                status = TunnelStatus(
                    phase: .idle, protection: .unprotected, transport: nil, health: .idle, recentEvents: PreviewFixtures.events,
                )
                return
            }
            var status = TunnelStatus(
                phase: .active(Generation(rawValue: 3)), protection: .protected, transport: nil,
                health: TunnelHealth(level: .healthy, lastHandshake: now.addingTimeInterval(-18), rxRate: 0, txRate: 0),
                recentEvents: PreviewFixtures.events,
            )
            status.activeProfileID = home.id
            self.status = status
            activeProfileID = home.id
            statisticsProfileID = home.id
            statistics = TunnelStatistics(
                generation: 3, sampledAt: now, interfaceName: "utun4", listenPort: nil,
                peers: [PeerStatistics(
                    publicKey: home.interface.publicKey, endpoint: home.peers.first?.endpoint,
                    lastHandshake: now.addingTimeInterval(-18), rxBytes: 1_284_301_824, txBytes: 88_080_384,
                    persistentKeepalive: 25,
                )],
            )
        }

        /// The dual-stack fixture named Home, as the Mac previews use it.
        private static func home() -> TunnelProfile {
            var profile = PreviewFixtures.profile
            profile.name = "Home"
            if let data = try? FixtureLoader.repository().data("conf/ipv6-dual-stack.conf") {
                var bytes = Array(data)
                if let parsed = try? parseWgQuick(&bytes, name: "Home") {
                    profile = parsed.profile
                    profile.original = nil
                }
            }
            return profile
        }

        private static let log = """
        2027-01-15 08:00:01Z app  Starting Home
        2027-01-15 08:00:01Z ext  Interface utun4 up, MTU 1420
        2027-01-15 08:00:02Z ext  Handshake completed with peer 1
        2027-01-15 08:00:02Z app  Home is active
        """

        public func watchLog() async {}
        public func exportLog() -> Data {
            Data(logText.utf8)
        }

        public func exportArchive() async throws -> URL {
            throw CocoaError(.featureUnsupported)
        }

        public func toggleConnection() async {
            if let id = selectedProfileID {
                await setTunnel(id, on: !isTunnelOn(id))
            }
        }

        public func setTunnel(_ id: UUID, on: Bool) async {
            activeProfileID = on ? id : nil
            status.activeProfileID = activeProfileID
            status.phase = on ? .active(Generation(rawValue: 3)) : .idle
            status.protection = on ? .protected : .unprotected
        }

        public func watchStatistics() async {}
        public func deleteProfile(_ id: UUID) async {
            profiles.removeAll { $0.id == id }
        }

        public func prepareImport(_: String) {}
        public func prepareScannedCode(_: String) {}
        public func reportScanFailure(_: IOSScanFailure) {}
        public func importFile(at _: URL) {}
        public func createFromScratch() {}
        public func skipReview() {
            if !pendingReviews.isEmpty {
                pendingReviews.removeFirst()
            }
        }

        public func cancelImport() {
            pendingReviews = []
        }

        public func confirmImport() async {
            skipReview()
        }

        public func importReviewed(_ profile: TunnelProfile, secrets _: borrowing ParsedSecrets, connect _: Bool) throws {
            profiles.append(profile)
            skipReview()
        }

        public func deleteProfiles(at offsets: IndexSet) async {
            profiles.remove(atOffsets: offsets)
        }

        public func moveProfiles(from offsets: IndexSet, to destination: Int) {
            profiles.move(fromOffsets: offsets, toOffset: destination)
        }

        public func openEditor(_: TunnelProfile) async {}
        public func saveEditor(_: TunnelProfile, secrets _: borrowing ParsedSecrets) throws {}
        public func closeEditor() {
            editor = nil
        }

        public func savePreferences() async {}
    }

    /// The real iPhone and iPad screens on ``IOSPreviewModel``, as the picture harness renders them.
    public struct IOSScreenPreview: View {
        public enum Screen: String, CaseIterable, Sendable {
            /// The first screen: Tunnels, Settings and Add Tunnel… (the iPad sidebar).
            case home
            /// Home's page with the tunnel on.
            case tunnelActive
            /// Cabin's page with every tunnel off.
            case tunnelInactive
            /// The Add a Tunnel sheet's sources.
            case addTunnel
            case protection, log, about
            /// The first setup step.
            case onboarding
            /// The whole window; on iPad, the split view with the active tunnel selected.
            case split
            /// IOSSheetParts alone: a first screen and a tunnel page built only from the parts, as the restyle targets.
            case partsList, partsForm
            /// The tunnel editor on the Home fixture, presented in a sheet as the tunnel page presents it: its top, the whole
            /// form (the harness renders it tall), and with errors. On iPad the full-screen editor instead, so the form width
            /// shows.
            case editor, editorFull, editorErrors
            /// The whole editor with long values, and at the second accessibility text size (both rendered tall).
            case editorLong, editorLargeText
            /// The editor's top in a sheet on iPhone and iPad.
            case editorSheet
            /// A preshared key with its one reveal in use (a 44-character key wraps), at the default and the second larger
            /// text size.
            case secretRevealed, secretRevealedLarge
        }

        private let screen: Screen
        @State private var model: IOSPreviewModel

        public init(_ screen: Screen) {
            self.screen = screen
            _model = State(initialValue: IOSPreviewModel(active: screen != .tunnelInactive, onboarded: screen != .onboarding))
        }

        /// The pages and the Add a Tunnel sheet take the shell's accent tint, as they do inside the app's window.
        public var body: some View {
            page.tint(IOSDesign.accent)
        }

        @ViewBuilder private var page: some View {
            switch screen {
            case .home, .split: IOSShellScreen(model: model)
            case .tunnelActive: NavigationStack { IOSTunnelPage(model: model, profileID: model.profiles[0].id) }
            case .tunnelInactive: NavigationStack { IOSTunnelPage(model: model, profileID: model.profiles[1].id) }
            case .addTunnel: IOSAddTunnelSheet(model: model, createEmpty: {}, onDone: {})
            case .protection: NavigationStack { IOSProtectionPage(model: model) }
            case .log: NavigationStack { IOSLogScreen(model: model) }
            case .about: NavigationStack { IOSAboutPage(engineVersion: model.engineVersion) }
            case .onboarding: IOSOnboardingScreen(model: model)
            case .partsList: IOSPartsListSample(model: model)
            case .partsForm: IOSPartsFormSample(model: model)
            // The harness's full-screen navigation stack draws an empty band above its bar that a presented sheet does not
            // have, so the iPhone editor pictures present the editor as the app does.
            case .editor where isPad: IOSEditorSample(try? EditorPreviewScenario.valid.makeModel())
            case .editor, .editorFull, .editorSheet: IOSEditorSheetSample { try? EditorPreviewScenario.valid.makeModel() }
            case .editorErrors: IOSEditorSheetSample { try? EditorPreviewScenario.errors.makeModel() }
            case .editorLong: IOSEditorSheetSample { try? EditorLongValuesFixture.makeModel() }
            case .editorLargeText: IOSEditorSheetSample(typeSize: .accessibility2) { try? EditorLongValuesFixture.makeModel() }
            case .secretRevealed: IOSRevealedSecretSample()
            case .secretRevealedLarge: IOSRevealedSecretSample().dynamicTypeSize(.xxLarge)
            }
        }

        private var isPad: Bool {
            UIDevice.current.userInterfaceIdiom == .pad
        }
    }

    /// The editor sheet's content as the tunnel page presents it: ProfileEditorForm in a navigation stack, titled for Home.
    private struct IOSEditorSample: View {
        @State private var editor: ProfileEditorModel?

        init(_ model: ProfileEditorModel?) {
            _editor = State(initialValue: model)
        }

        var body: some View {
            NavigationStack {
                if let editor {
                    ProfileEditorForm(
                        model: editor, onSave: { _, _ in }, onCancel: {}, title: MacStrings.editTunnelTitle("Home"),
                    )
                }
            }
        }
    }

    /// The editor presented in a sheet, at once and without animation, over the page background.
    private struct IOSEditorSheetSample: View {
        private let typeSize: DynamicTypeSize?
        private let makeModel: () -> ProfileEditorModel?
        @State private var presented = false

        init(typeSize: DynamicTypeSize? = nil, model: @escaping () -> ProfileEditorModel?) {
            self.typeSize = typeSize
            makeModel = model
        }

        var body: some View {
            IOSDesign.pageBackground.ignoresSafeArea()
                .sheet(isPresented: $presented) {
                    if let typeSize {
                        IOSEditorSample(makeModel()).dynamicTypeSize(typeSize)
                    } else {
                        IOSEditorSample(makeModel())
                    }
                }
                .task {
                    var transaction = Transaction()
                    transaction.disablesAnimations = true
                    withTransaction(transaction) { presented = true }
                }
        }
    }

    /// A preshared key card with the key revealed, as the editor shows it after Reveal: the key wraps, the icon buttons
    /// sit on its first line.
    private struct IOSRevealedSecretSample: View {
        /// A key-shaped stand-in, 44 characters as a WireGuard key, built so it is plainly not one.
        private static let key = String(String(repeating: "wgex", count: 11).dropLast()) + "="

        var body: some View {
            NavigationStack {
                List {
                    Section {
                        SecretField(EditorStrings.presharedKey, copier: SecretCopyController(), onCommit: { _ in }) { Self.key }
                            .previewRevealed(Self.key)
                            .iosCardRow(.only)
                    } header: {
                        IOSGroupHeading(EditorStrings.peers).iosListHeader()
                    }
                }
                .font(IOSDesign.field)
                .iosCardList()
                .navigationTitle("Revealed key")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    /// A first screen made only of the list parts: first-screen headings, card rows and Add Tunnel… alone at the foot.
    private struct IOSPartsListSample: View {
        let model: IOSPreviewModel
        @State private var selection: Int?

        var body: some View {
            NavigationStack {
                List(selection: $selection) {
                    Section {
                        ForEach(Array(model.profiles.enumerated()), id: \.offset) { index, profile in
                            NavigationLink(value: index) {
                                LabeledContent(profile.name, value: index == 0 ? "Active" : "")
                            }
                            .iosCardRow(IOSCardRowPosition(index: index, count: model.profiles.count), selected: selection == index)
                        }
                    } header: {
                        IOSFirstScreenHeading("Tunnels").iosListHeader()
                    }
                    Section {
                        let pages = ["General", "Protection", "Log", "About"]
                        ForEach(Array(pages.enumerated()), id: \.offset) { index, page in
                            NavigationLink(value: 10 + index) { Text(page) }
                                .iosCardRow(IOSCardRowPosition(index: index, count: pages.count))
                        }
                    } header: {
                        IOSFirstScreenHeading("Settings").iosListHeader()
                    }
                    Section {
                        Button("Add Tunnel…") {}.iosCardRow(.only)
                    }
                }
                .iosCardList()
                .navigationTitle("WGEX")
                .toolbar { ToolbarItem { EditButton() } }
            }
        }
    }

    /// A tunnel page made only of the form parts: the status row, value rows, a link row and the three buttons.
    private struct IOSPartsFormSample: View {
        let model: IOSPreviewModel
        @State private var on = true

        var body: some View {
            NavigationStack {
                Form {
                    Section {
                        Toggle(isOn: $on) {
                            Text(on ? "Active" : "Inactive").foregroundStyle(on ? IOSDesign.success : IOSDesign.text)
                            Text("Connected for 3 h 12 min")
                        }
                    }
                    Section("Traffic") {
                        LabeledContent("Download", value: "1.28 GB")
                        LabeledContent("Upload", value: "88.1 MB")
                        LabeledContent("Latest handshake", value: "18 s ago")
                    }
                    Section {
                        LabeledContent("Tunnel address", value: "10.8.0.2/32")
                        NavigationLink {} label: { LabeledContent("Routes", value: "All traffic") }
                            .buttonStyle(.iosRowLink)
                    } header: {
                        Text("Addresses")
                    } footer: {
                        Text("A footer note in footnote, textSecondary.")
                    }
                    Section("Buttons") {
                        HStack(spacing: IOSDesign.Space.medium) {
                            Button("Add") {}.buttonStyle(.iosSecondary)
                            Button("Add and Activate") {}.buttonStyle(.iosPrimary)
                            Spacer(minLength: 0)
                        }
                        Button("Delete Tunnel…", role: .destructive) {}
                    }
                    Section {
                        // As the tunnel page has it: full width, centred.
                        Button(role: .destructive) {} label: { Text("Delete Tunnel…").frame(maxWidth: .infinity) }
                            .buttonStyle(.iosDestructive)
                    }
                }
                .formStyle(.iosCards)
                .navigationTitle("Home")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    #Preview("iPhone first screen") { IOSScreenPreview(.home) }
    #Preview("iPhone first screen, dark") { IOSScreenPreview(.home).preferredColorScheme(.dark) }
    #Preview("iPhone tunnel, active") { IOSScreenPreview(.tunnelActive) }
    #Preview("iPhone tunnel, inactive, dark") { IOSScreenPreview(.tunnelInactive).preferredColorScheme(.dark) }
    #Preview("Add a Tunnel") { IOSScreenPreview(.addTunnel) }
    #Preview("Protection") { IOSScreenPreview(.protection) }
    #Preview("Log") { IOSScreenPreview(.log) }
    #Preview("About") { IOSScreenPreview(.about) }
    #Preview("Setup, first step") { IOSScreenPreview(.onboarding) }
    #Preview("iPad split view", traits: .landscapeLeft) { IOSScreenPreview(.split) }
    #Preview("Parts, first screen") { IOSScreenPreview(.partsList) }
    #Preview("Parts, tunnel page, dark") { IOSScreenPreview(.partsForm).preferredColorScheme(.dark) }
    #Preview("Editor") { IOSScreenPreview(.editor) }
    #Preview("Editor, errors, dark") { IOSScreenPreview(.editorErrors).preferredColorScheme(.dark) }
#endif
