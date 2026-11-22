// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import SwiftUI
    import WGEXCore

    public struct MacMainWindowView: View {
        @Bindable private var model: MacShellModel
        private let edit: () -> Void
        private let export: () -> Void
        private let exportAll: () -> Void
        private let addProfile: () -> Void
        private let paste: () -> Void
        private let acknowledgements: String
        private let revisit: (MacOnboardingStep) -> Void
        private let simulateApproval: () -> Void
        @State private var pendingDeletion: TunnelProfile?

        public init(
            model: MacShellModel,
            edit: @escaping () -> Void = {},
            export: @escaping () -> Void = {},
            exportAll: @escaping () -> Void = {},
            addProfile: @escaping () -> Void = {},
            paste: @escaping () -> Void = {},
            acknowledgements: String = MacStrings.acknowledgementsCouldNotBeLoaded,
            revisit: @escaping (MacOnboardingStep) -> Void = { _ in },
            simulateApproval: @escaping () -> Void = {},
        ) {
            self.model = model; self.edit = edit; self.export = export; self.exportAll = exportAll
            self.addProfile = addProfile; self.paste = paste
            self.acknowledgements = acknowledgements; self.revisit = revisit; self.simulateApproval = simulateApproval
        }

        public var body: some View {
            NavigationSplitView {
                sidebar
            } detail: {
                Group {
                    if model.showsSettings {
                        MacSettingsView(
                            model: model, acknowledgements: acknowledgements, revisit: revisit, simulateApproval: simulateApproval,
                        )
                    } else if model.profiles.isEmpty {
                        MacEmptyTunnelsView(model: model, addProfile: addProfile, paste: paste)
                    } else if let profile = model.selectedProfile {
                        MacTunnelPage(model: model, profile: profile, edit: edit, export: export) { pendingDeletion = $0 }
                            .id(profile.id)
                    }
                }
                .background(MacDesign.pageBackground)
                .toolbar(removing: .title)
                .navigationTitle(model.showsSettings ? model.settingsTab.title : model.selectedProfile?.name ?? MacStrings.appName)
                .overlay(alignment: .bottom) {
                    if let message = model.operationMessage {
                        MacToast(message, dismiss: model.dismissMessage).padding(24).frame(maxWidth: 640)
                    }
                }
            }
            .macUninstallOffer(model.uninstall)
            .macDeleteTunnelAlert(model: model, pending: $pendingDeletion)
            .frame(minWidth: 1000, minHeight: 700)
            .accessibilityElement(children: .contain)
            .wgexAX(.main, "surface", label: model.detailPresentation.accessibilityLabel)
        }

        private var sidebar: some View {
            VStack(spacing: 0) {
                List(selection: $model.windowSelection) {
                    Section {
                        ForEach(model.profiles) { profile in
                            let selected = model.windowSelection == .tunnel(profile.id)
                            HStack {
                                Text(profile.name).lineLimit(1)
                                    .foregroundStyle(selected ? AnyShapeStyle(.primary) : AnyShapeStyle(MacDesign.text))
                                Spacer()
                                if let state = model.sidebarState(profile) {
                                    Text(state).font(MacDesign.sidebarStatus)
                                        .foregroundStyle(selected ? AnyShapeStyle(.secondary) : AnyShapeStyle(MacDesign.textSecondary))
                                        .lineLimit(1)
                                }
                            }
                            .padding(.vertical, 3)
                            .accessibilityElement(children: .combine)
                            .tag(MacWindowSelection.tunnel(profile.id))
                            .disabled(!model.canSelectProfile)
                            .contextMenu {
                                Button(MacStrings.deleteProfileAction, role: .destructive) { pendingDeletion = profile }
                                    .wgexControl(.main, "deleteProfile", label: MacStrings.deleteProfileAction, item: profile.id.uuidString)
                            }
                            .wgexControl(
                                .main, "tunnel",
                                label: MacStrings.profileRowLabel(profile.name, state: model.sidebarState(profile) ?? MacStrings.inactive),
                                item: profile.id.uuidString, inputLabel: profile.name,
                            )
                            .accessibilityValue(profile.name)
                        }
                    } header: {
                        MacSidebarHeading(MacStrings.tunnels)
                    }
                    Section {
                        ForEach(MacSettingsTab.sidebarPages) { tab in
                            let selected = model.windowSelection == .settings(tab)
                            Text(tab.title).lineLimit(1)
                                .foregroundStyle(selected ? AnyShapeStyle(.primary) : AnyShapeStyle(MacDesign.text))
                                .padding(.vertical, 3)
                                .tag(MacWindowSelection.settings(tab))
                                .wgexControl(.settings, "tab", label: tab.title, item: tab.rawValue)
                        }
                    } header: {
                        MacSidebarHeading(MacStrings.settingsTitle)
                    }
                }
                .scrollContentBackground(.hidden)
                .tint(MacDesign.accent)
                .wgexAX(.main, "profiles", label: MacStrings.tunnels)
                Divider()
                Button(MacStrings.addTunnel, action: addProfile)
                    .wgexControl(.main, "sidebarImport", label: MacStrings.addTunnel)
                    .buttonStyle(.borderless)
                    .font(MacDesign.body.weight(.medium))
                    .foregroundStyle(MacDesign.accent)
                    .lineLimit(1)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(MacDesign.sidebarBackground)
            .navigationSplitViewColumnWidth(min: 220, ideal: 250, max: 300)
        }
    }
#endif
