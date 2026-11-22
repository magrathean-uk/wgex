// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import UIKit
    import WGEXCore

    /// A page of the first screen's list.
    public enum IOSPage: Hashable, Sendable {
        case tunnel(UUID), general, protection, log, about
    }

    /// The app's one window (SPEC 10): the Mac sidebar's content as a grouped list (tunnels with their state, then
    /// General, Protection, Log and About, then Add Tunnel… in its own group). iPad shows the list beside the page;
    /// iPhone pushes the page. `debug` adds a test-build page to General's navigation bar.
    public struct IOSShellScreen<Model: IOSAppState, Debug: View>: View {
        private struct AddRequest: Identifiable {
            let id = UUID()
            let source: IOSImportSource
        }

        private let model: Model
        private let debug: () -> Debug
        @State private var selection: IOSPage?
        @State private var column: NavigationSplitViewColumn = .sidebar
        @State private var adding: AddRequest?
        @State private var editing = false
        @State private var chosenFirst = false
        @Environment(\.horizontalSizeClass) private var sizeClass

        public init(model: Model, @ViewBuilder debug: @escaping () -> Debug) {
            self.model = model
            self.debug = debug
        }

        public var body: some View {
            NavigationSplitView(preferredCompactColumn: $column) {
                IOSHomeList(model: model, selection: $selection, marksSelection: sizeClass == .regular) { add(.review) }
                    .navigationSplitViewColumnWidth(min: 260, ideal: 300, max: 360)
            } detail: {
                NavigationStack { page(selection) }
            }
            .tint(IOSDesign.accent)
            .fullScreenCover(isPresented: Binding(get: { !model.onboardingComplete }, set: { model.onboardingComplete = !$0 })) {
                IOSOnboardingScreen(model: model)
            }
            .sheet(item: $adding, onDismiss: dismissedAdd) { request in
                IOSAddTunnelSheet(model: model, initialSource: request.source, createEmpty: createEmpty) { adding = nil }
            }
            .iosEditorSheet(model: model, isPresented: $editing)
            // Open In and the share sheet queue a review while no sheet is up; show it in the Add a Tunnel sheet.
            .onChange(of: model.review == nil, initial: true) { _, empty in
                if !empty, adding == nil, !editing, model.onboardingComplete {
                    add(.review)
                }
            }
            .onChange(of: model.profiles.map(\.id), initial: true) { _, ids in
                if case let .tunnel(id) = selection, !ids.contains(id) {
                    selection = nil
                }
                chooseFirstPage(ids)
            }
            .onChange(of: model.activeProfileID) { _, _ in chooseFirstPage(model.profiles.map(\.id)) }
        }

        @ViewBuilder private func page(_ page: IOSPage?) -> some View {
            switch page {
            case let .tunnel(id): IOSTunnelPage(model: model, profileID: id).id(id)
            case .general:
                IOSGeneralPage(model: model).toolbar {
                    if Debug.self != EmptyView.self {
                        ToolbarItem { NavigationLink("Debug", destination: debug) }
                    }
                }
            case .protection: IOSProtectionPage(model: model)
            case .log: IOSLogScreen(model: model)
            case .about: IOSAboutPage(engineVersion: model.engineVersion)
            case nil:
                ContentUnavailableView {
                    Label(MacStrings.noTunnelsTitle, systemImage: "network")
                } description: {
                    Text(PlatformStrings.addAConfigurationMadeForThisDevice)
                } actions: {
                    Button(MacStrings.addTunnel) { add(.review) }
                }
            }
        }

        /// On iPad the window opens on the active tunnel, else the first (SPEC 5.1); iPhone opens on the list.
        private func chooseFirstPage(_ ids: [UUID]) {
            guard sizeClass == .regular, !chosenFirst, selection == nil, let first = model.activeProfileID ?? ids.first else { return }
            chosenFirst = true
            selection = .tunnel(first)
        }

        private func add(_ source: IOSImportSource) {
            adding = AddRequest(source: source)
        }

        private func dismissedAdd() {
            // Leaving the sheet by a swipe drops any review it was showing; Create Empty Tunnel opens the editor next.
            if model.editor == nil {
                model.cancelImport()
            } else {
                editing = true
            }
        }

        private func createEmpty() {
            model.cancelImport()
            model.createFromScratch()
            adding = nil
        }
    }

    public extension IOSShellScreen where Debug == EmptyView {
        init(model: Model) {
            self.init(model: model) { EmptyView() }
        }
    }

    /// The first screen's grouped list. Tunnels show a short state word after the name only when not inactive.
    private struct IOSHomeList<Model: IOSAppState>: View {
        let model: Model
        @Binding var selection: IOSPage?
        /// True where the list stays beside the page (iPad). Read from the window: the sidebar column itself is compact.
        let marksSelection: Bool
        let add: () -> Void
        @Environment(\.dynamicTypeSize) private var typeSize

        private let settingsPages: [(page: IOSPage, title: String)] = [
            (.general, MacStrings.general), (.protection, MacStrings.protection),
            (.log, MacStrings.rawLog), (.about, MacStrings.about),
        ]

        var body: some View {
            List(selection: $selection) {
                tunnelsSection
                settingsSection
                addSection
            }
            .iosCardList()
            .navigationTitle(MacStrings.appName)
            .toolbar { ToolbarItem { EditButton() } }
        }

        /// The sidebar's open page is marked only where the list stays beside the page (iPad).
        private func isSelected(_ page: IOSPage) -> Bool {
            marksSelection && selection == page
        }

        private var tunnelsSection: some View {
            Section {
                if model.profiles.isEmpty {
                    Text(PlatformStrings.addAConfigurationMadeForThisDevice).foregroundStyle(IOSDesign.textSecondary)
                        .iosCardRow(.only)
                }
                ForEach(Array(model.profiles.enumerated()), id: \.element.id) { index, profile in
                    NavigationLink(value: IOSPage.tunnel(profile.id)) { tunnelLabel(profile) }
                        .accessibilityIdentifier("wgex.tunnel.row.\(profile.id.uuidString)")
                        .iosCardRow(
                            IOSCardRowPosition(index: index, count: model.profiles.count),
                            selected: isSelected(.tunnel(profile.id)),
                        )
                }
                .onDelete { offsets in Task { await model.deleteProfiles(at: offsets) } }
                .onMove { model.moveProfiles(from: $0, to: $1) }
            } header: {
                IOSFirstScreenHeading(MacStrings.tunnels).iosListHeader()
            }
        }

        /// The name, truncated in the middle so both ends of a long name stay visible, with the state word kept whole
        /// beside it; at accessibility text sizes the name takes up to three lines with the word under it.
        @ViewBuilder private func tunnelLabel(_ profile: TunnelProfile) -> some View {
            let word = IOSTunnelPagePresentation.listWord(
                profileID: profile.id, status: model.status,
                activeProfileID: model.activeProfileID, userInitiated: model.userInitiated,
            )
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                    Text(profile.name).foregroundStyle(IOSDesign.text).lineLimit(3).truncationMode(.middle)
                    if let word {
                        Text(word).foregroundStyle(IOSDesign.textSecondary).monospacedDigit()
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(spacing: IOSDesign.Space.medium) {
                    Text(profile.name).foregroundStyle(IOSDesign.text).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: IOSDesign.Space.small)
                    if let word {
                        Text(word).foregroundStyle(IOSDesign.textSecondary).monospacedDigit().lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                            .layoutPriority(1)
                    }
                }
            }
        }

        private var settingsSection: some View {
            Section {
                ForEach(Array(settingsPages.enumerated()), id: \.offset) { index, entry in
                    NavigationLink(value: entry.page) { Text(entry.title).foregroundStyle(IOSDesign.text) }
                        .iosCardRow(IOSCardRowPosition(index: index, count: settingsPages.count), selected: isSelected(entry.page))
                }
            } header: {
                IOSFirstScreenHeading(PlatformStrings.settingsGroup).iosListHeader()
            }
        }

        private var addSection: some View {
            Section {
                Button(MacStrings.addTunnel, action: add)
                    .accessibilityIdentifier("wgex.addProfile")
                    .foregroundStyle(IOSDesign.accent)
                    .iosCardRow(.only)
            } footer: {
                if let message = model.operationMessage {
                    Text(message).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary).iosListHeader()
                }
            }
        }
    }
#endif
