// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import SwiftUI
    import WGEXCore

    /// General (SPEC 8.1): default tunnel, Dock and notifications. Start-up stays per tunnel on the tunnel page (E1).
    package struct MacGeneralPage: View {
        @Bindable private var model: MacShellModel

        package init(model: MacShellModel) {
            self.model = model
        }

        package var body: some View {
            Form {
                Section {
                    MacControlRow {
                        Picker(selection: $model.selectedProfileID) {
                            Text(MacStrings.chooseATunnel).lineLimit(1).tag(UUID?.none)
                            ForEach(model.profiles) { profile in Text(profile.name).lineLimit(1).tag(Optional(profile.id)) }
                        } label: {
                            Text(MacStrings.defaultTunnel).lineLimit(1)
                        }
                        .labelsHidden()
                        .wgexControl(.protection, "defaultTunnel", label: MacStrings.defaultTunnel)
                        .disabled(!model.canSelectProfile)
                    } label: {
                        Text(MacStrings.defaultTunnel).lineLimit(1)
                    }
                    MacControlRow {
                        Toggle(isOn: MacAppPagesPresentation.showsDockIcon(model)) {
                            Text(MacStrings.showWGEXInTheDock).lineLimit(1)
                        }
                        .toggleStyle(.switch).labelsHidden()
                        .wgexControl(.settings, "hideDockIcon", label: MacStrings.showWGEXInTheDock)
                    } label: {
                        Text(MacStrings.showWGEXInTheDock).lineLimit(1)
                    }
                    MacControlRow {
                        Toggle(isOn: model.globalSetting(\.notifications)) {
                            Text(MacStrings.notifyMeWhenProtectionChanges).lineLimit(1)
                            Text(MacStrings.notificationDeliveryArrivesInA)
                        }
                        .toggleStyle(.switch).labelsHidden()
                        .wgexControl(.settings, "protectionNotifications", label: MacStrings.notifyMeWhenProtectionChanges)
                        .disabled(model.hostGuarded || model.busy)
                    } label: {
                        Text(MacStrings.notifyMeWhenProtectionChanges).lineLimit(1)
                        Text(MacStrings.notificationDeliveryArrivesInA)
                    }
                } footer: {
                    Text(MacStrings.quittingDoesNotDisconnectTheTunnel).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                }
            }
            .formStyle(.macCards(title: MacSettingsTab.general.title))
        }
    }
#endif
