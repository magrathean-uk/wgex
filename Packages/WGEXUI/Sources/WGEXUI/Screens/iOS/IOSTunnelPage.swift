// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import UIKit
    import WGEXCore

    /// One tunnel (SPEC 5.2 carried to iOS by SPEC 10): the status word with the on/off switch at the top, as in the
    /// WireGuard app, then the Mac page's groups. Counters are sampled only while this page is visible and the app is
    /// active. Edit is in the navigation bar; Delete Tunnel… is at the foot.
    public struct IOSTunnelPage<Model: IOSAppState>: View {
        private let model: Model
        private let profileID: UUID
        @State private var editing = false
        @State private var confirmingDelete = false
        @Environment(\.scenePhase) private var scenePhase
        @Environment(\.dismiss) private var dismiss
        @Environment(\.dynamicTypeSize) private var typeSize

        public init(model: Model, profileID: UUID) {
            self.model = model
            self.profileID = profileID
        }

        public var body: some View {
            Group {
                if let profile = model.profiles.first(where: { $0.id == profileID }) {
                    TimelineView(.periodic(from: .now, by: 1)) { timeline in
                        content(profile, now: timeline.date)
                    }
                    .navigationTitle(profile.name)
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .primaryAction) {
                            Button(PlatformStrings.edit) { edit(profile) }
                                .disabled(model.isBusy)
                                .accessibilityIdentifier("wgex.tunnel.edit")
                        }
                    }
                    .alert(MacStrings.deleteTunnelTitle(profile.name), isPresented: $confirmingDelete) {
                        Button(MacStrings.deleteAction, role: .destructive) { delete() }
                        Button(MacStrings.cancel, role: .cancel) {}
                    } message: {
                        Text(model.isTunnelOn(profileID) ? MacStrings.tunnelWillBeDeactivatedFirst(profile.name) : MacStrings
                            .deleteCannotBeUndone)
                    }
                } else {
                    ContentUnavailableView(
                        MacStrings.noTunnelsTitle,
                        systemImage: "network",
                        description: Text(PlatformStrings.addAConfigurationMadeForThisDevice),
                    )
                }
            }
            // Visible and active only: hiding the page or leaving the app cancels the task, which stops sampling.
            .task(id: scenePhase == .active) {
                guard scenePhase == .active else { return }
                await model.watchStatistics()
            }
            .iosEditorSheet(model: model, isPresented: $editing)
        }

        private func content(_ profile: TunnelProfile, now: Date) -> some View {
            // Counters are attributed by the sample's own tunnel, never by whichever tunnel is active now.
            let sample = model.statisticsProfileID == profileID ? model.statistics : nil
            let page = IOSTunnelPagePresentation(
                profile: profile,
                status: model.status,
                activeProfileID: model.activeProfileID,
                userInitiated: model.userInitiated,
                statistics: sample,
                protection: model.protection,
                device: UIDevice.current.userInterfaceIdiom == .pad ? .iPad : .iPhone,
                now: now,
            )
            return Form {
                statusSection(page.status)
                ForEach(page.groups) { group in
                    Section {
                        ForEach(group.rows) { row in rowView(row, profile: profile, page: page) }
                    } header: {
                        Text(group.title)
                    } footer: {
                        if let note = group.note {
                            Text(note)
                                .accessibilityIdentifier("wgex.tunnel.exclusionWarning")
                        }
                    }
                }
                Section {
                    Button(role: .destructive) { confirmingDelete = true } label: {
                        Text(MacStrings.deleteTunnel).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.iosDestructive)
                    .disabled(model.isBusy)
                    .accessibilityIdentifier("wgex.tunnel.delete")
                }
            }
            .formStyle(.iosCards)
        }

        private func statusSection(_ status: IOSTunnelPagePresentation.Status) -> some View {
            Section {
                Toggle(isOn: Binding(
                    get: { model.isTunnelOn(profileID) },
                    set: { on in Task { await model.setTunnel(profileID, on: on) } },
                )) {
                    // The sheet's status colour: success while Active, the text colour in every other state.
                    Text(status.word).fontWeight(.semibold).monospacedDigit()
                        .foregroundStyle(status.state == .active ? IOSDesign.success : IOSDesign.text)
                    if let detail = status.detail {
                        Text(detail)
                    }
                }
                .disabled(model.isBusy || model.applyingProfileID == profileID)
                .accessibilityIdentifier("wgex.tunnel.switch")
                if model.applyingProfileID == profileID {
                    HStack(spacing: IOSDesign.Space.medium) {
                        ProgressView()
                        Text(PlatformStrings.applyingChanges)
                    }
                    .accessibilityIdentifier("wgex.tunnel.applying")
                }
                if let message = model.operationMessage {
                    Text(message).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                }
            }
        }

        @ViewBuilder private func rowView(_ row: TunnelPageRow, profile: TunnelProfile, page: IOSTunnelPagePresentation) -> some View {
            switch row.link {
            case .routes:
                NavigationLink { IOSListPage(title: MacStrings.routes, items: page.routes) } label: { labelled(row) }
                    .buttonStyle(.iosRowLink)
                    .contextMenu { copyButton(row) }
            case .exclusions:
                NavigationLink { IOSListPage(title: MacStrings.exclusions, items: page.exclusions) } label: { labelled(row) }
                    .buttonStyle(.iosRowLink)
                    .contextMenu { copyButton(row) }
            case .protectionPage:
                NavigationLink { IOSProtectionPage(model: model) } label: { labelled(row) }
                    .buttonStyle(.iosRowLink)
            case .onDemand:
                NavigationLink {
                    IOSOnDemandPage(profile: profile) { edit(profile) }
                } label: { labelled(row) }
                    .buttonStyle(.iosRowLink)
                    .accessibilityIdentifier("wgex.tunnel.onDemand")
            case .startup, nil:
                labelled(row).contextMenu { copyButton(row) }
            }
        }

        private func labelled(_ row: TunnelPageRow) -> some View {
            LabeledContent(row.label) {
                // One line beside the label; at accessibility text sizes the value sits under the label and may wrap.
                Text(row.value)
                    .font(row.monospaced ? IOSDesign.body.monospaced() : IOSDesign.body)
                    .monospacedDigit()
                    .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                    .truncationMode(.middle)
            }
            .accessibilityValue(row.copyValue)
        }

        private func copyButton(_ row: TunnelPageRow) -> some View {
            Button(MacStrings.copy, systemImage: "doc.on.doc") { UIPasteboard.general.string = row.copyValue }
        }

        private func edit(_ profile: TunnelProfile) {
            Task {
                await model.openEditor(profile)
                editing = model.editor != nil
            }
        }

        private func delete() {
            Task {
                await model.deleteProfile(profileID)
                if !model.profiles.contains(where: { $0.id == profileID }) {
                    dismiss()
                }
            }
        }
    }

    /// Every route or every exclusion of the tunnel, opened from the Routes or Exclusions row. A List, so a tunnel with
    /// hundreds of entries builds only the rows on screen.
    private struct IOSListPage: View {
        let title: String
        let items: [String]

        var body: some View {
            List {
                Section {
                    ForEach(Array(items.enumerated()), id: \.element) { index, item in
                        Text(item).monospacedDigit().textSelection(.enabled)
                            .foregroundStyle(IOSDesign.text)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .iosCardRow(IOSCardRowPosition(index: index, count: items.count))
                    }
                } header: {
                    IOSGroupHeading(title).iosListHeader()
                }
            }
            .iosCardList()
            .navigationTitle(title)
        }
    }

    /// The tunnel's on-demand rule in words, opened from the Connect on demand row as the Mac opens its sheet; the
    /// rules themselves are set with Edit, in the editor's on-demand group (M06-T06).
    private struct IOSOnDemandPage: View {
        let profile: TunnelProfile
        let edit: () -> Void

        var body: some View {
            let form = IOSOnDemandForm(policy: profile.onDemand)
            Form {
                Section {
                    LabeledContent(IOSOnDemandStrings.detailRow, value: form.activationSummary)
                    if let ssids = form.ssidSummary {
                        LabeledContent(IOSOnDemandStrings.ssids, value: ssids).textSelection(.enabled)
                    }
                }
                Section {
                    Button(MacStrings.editEllipsis, action: edit)
                        .accessibilityIdentifier("wgex.tunnel.onDemandEdit")
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.connectOnDemand)
        }
    }

    /// The tunnel editor sheet, shared by Add Tunnel (create from scratch) and the tunnel page (edit).
    package struct IOSEditorSheet<Model: IOSAppState>: ViewModifier {
        package let model: Model
        @Binding package var isPresented: Bool

        package func body(content: Content) -> some View {
            content
                .onChange(of: model.editor == nil) {
                    _, empty in if empty {
                        isPresented = false
                    }
                }
                .sheet(isPresented: $isPresented, onDismiss: { model.closeEditor() }) {
                    if let editor = model.editor {
                        NavigationStack {
                            // "Add current network" needs the tunnel's VPN configuration, installed by its first save.
                            let installed = model.profiles.first { $0.id == editor.sourceProfile.id }
                            ProfileEditorForm(
                                model: editor,
                                onSave: { profile, secrets in try model.saveEditor(profile, secrets: secrets) },
                                onCancel: { isPresented = false },
                                connectedNetwork: installed != nil ? model.connectedNetwork : nil,
                                title: installed.map { MacStrings.editTunnelTitle($0.name) } ?? MacStrings.newTunnelTitle,
                            )
                            .disabled(model.isBusy)
                            .interactiveDismissDisabled(model.isBusy)
                            .safeAreaInset(edge: .bottom) {
                                if model.applyingProfileID != nil {
                                    HStack(spacing: IOSDesign.Space.medium) {
                                        ProgressView()
                                        Text(PlatformStrings.applyingChanges)
                                    }
                                    .font(.footnote).padding().background(.background)
                                } else if let message = model.operationMessage {
                                    Text(message).font(.footnote).padding().background(.background)
                                }
                            }
                        }
                    }
                }
        }
    }

    package extension View {
        func iosEditorSheet(model: some IOSAppState, isPresented: Binding<Bool>) -> some View {
            modifier(IOSEditorSheet(model: model, isPresented: isPresented))
        }
    }
#endif
