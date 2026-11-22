// SPDX-License-Identifier: MIT
#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// The per-profile on-demand editor of the official Mac app: Ethernet, Wi-Fi, and any, included or excluded Wi-Fi networks.
    /// It edits the draft only; the owner saves it and the daemon evaluates it (ADR-030).
    package struct MacOnDemandSection: View {
        @Bindable package var model: ProfileEditorModel
        package let connectedNetwork: (() async -> ConnectedNetworkReading)?
        @State private var listMessage: String?

        package var body: some View {
            Section(MacStrings.onDemandSection) {
                MacRowCaption(MacStrings.onDemandExplainer)
                MacSwitchRow(MacStrings.onDemandEthernet) {
                    Toggle(MacStrings.onDemandEthernet, isOn: $model.draft.onDemandForm.ethernet)
                        .wgexControl(.editor, "onDemandEthernet", label: MacStrings.onDemandEthernet)
                }
                MacSwitchRow(MacStrings.onDemandWiFi) {
                    Toggle(MacStrings.onDemandWiFi, isOn: $model.draft.onDemandForm.wifi)
                        .wgexControl(.editor, "onDemandWiFi", label: MacStrings.onDemandWiFi)
                }
                if !model.draft.onDemandForm.isEnabled {
                    MacRowCaption(MacStrings.onDemandOffNote)
                }
                if model.draft.onDemandForm.wifi {
                    MacControlRow {
                        Picker(MacStrings.onDemandNetworks, selection: $model.draft.onDemandForm.match) {
                            Text(MacStrings.onDemandAnyNetwork).tag(MacOnDemandForm.NetworkMatch.any)
                            Text(MacStrings.onDemandOnlyNetworks).tag(MacOnDemandForm.NetworkMatch.only)
                            Text(MacStrings.onDemandExceptNetworks).tag(MacOnDemandForm.NetworkMatch.except)
                        }.labelsHidden().fixedSize().wgexControl(.editor, "onDemandNetworks", label: MacStrings.onDemandNetworks)
                    } label: {
                        Text(MacStrings.onDemandNetworks).lineLimit(1)
                    }
                    if model.draft.onDemandForm.usesList {
                        listRows
                        MacRowCaption(MacStrings.onDemandLocationNote)
                    }
                }
                if model.draft.onDemandForm.isEnabled {
                    MacRowCaption(MacStrings.onDemandLockdownNote)
                }
                EditorFieldBadge(model: model, field: .onDemand)
            }
        }

        @ViewBuilder private var listRows: some View {
            ForEach($model.draft.onDemandForm.networks) { $network in
                MacFieldRow {
                    HStack(spacing: 8) {
                        TextField(
                            MacStrings.onDemandNetworkName, text: $network.name,
                            prompt: MacEditField.prompt(MacStrings.onDemandNetworkName),
                        )
                        .autocorrectionDisabled()
                        .wgexControl(
                            .editor, "onDemandNetwork", label: MacStrings.onDemandNetworkName, item: network.id.uuidString,
                        )
                        Button(MacStrings.onDemandRemoveNetwork, systemImage: "minus.circle") {
                            model.draft.onDemandForm.networks.removeAll { $0.id == network.id }
                            listMessage = nil
                        }
                        .labelStyle(.iconOnly).buttonStyle(.borderless).foregroundStyle(MacDesign.error)
                        .wgexControl(
                            .editor, "onDemandRemoveNetwork", label: MacStrings.onDemandRemoveNetwork, item: network.id.uuidString,
                        )
                    }
                } label: {
                    Text(MacStrings.onDemandNetworkName).lineLimit(1)
                }
            }
            HStack(spacing: 8) {
                Button(MacStrings.onDemandAddNetwork) {
                    model.draft.onDemandForm.addBlankRow(); listMessage = nil
                }
                .disabled(model.draft.onDemandForm.networks.count >= MacOnDemandForm.maximumNetworks)
                .wgexControl(.editor, "onDemandAddNetwork", label: MacStrings.onDemandAddNetwork)
                if connectedNetwork != nil {
                    Button(MacStrings.onDemandAddConnected) { Task { await addConnected() } }
                        .disabled(model.draft.onDemandForm.networks.count >= MacOnDemandForm.maximumNetworks)
                        .wgexControl(.editor, "onDemandAddConnected", label: MacStrings.onDemandAddConnected)
                }
            }
            if model.draft.onDemandForm.savesAsAnyNetwork {
                MacRowCaption(MacStrings.onDemandEmptyListNote, tone: .caution)
            }
            if let listMessage {
                MacRowCaption(listMessage, tone: .caution)
            }
        }

        /// Reads the connected network through the app's CoreWLAN adapter; Location is requested there, on this action.
        private func addConnected() async {
            guard let connectedNetwork else { return }
            switch await connectedNetwork() {
            case let .ssid(name):
                switch model.draft.onDemandForm.add(name) {
                case .added: listMessage = nil
                case .alreadyListed: listMessage = MacStrings.onDemandConnectedAlreadyListed
                case .listFull: listMessage = MacStrings.onDemandListLimit
                }
            case .notAssociated: listMessage = MacStrings.onDemandConnectedNotWiFi
            case .notAuthorised: listMessage = MacStrings.onDemandConnectedNeedsLocation
            case .unreadable: listMessage = MacStrings.onDemandConnectedUnreadable
            }
        }
    }
#endif
