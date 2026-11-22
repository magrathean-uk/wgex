// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// Protection (SPEC 8.2): the kill switch as a state, Lockdown, Allow local network, the sign-in window length and
    /// what WGEX cannot protect. Each setting is a control on this page only.
    package struct MacProtectionPage: View {
        @Bindable private var model: MacShellModel

        package init(model: MacShellModel) {
            self.model = model
        }

        package var body: some View {
            let killSwitch = model.killSwitchWord(for: nil)
            Form {
                Section {
                    LabeledContent {
                        Text(killSwitch).lineLimit(1).fixedSize()
                    } label: {
                        Text(MacStrings.killSwitch).lineLimit(1)
                        Text(MacStrings.killSwitchNote)
                    }
                    .accessibilityElement(children: .ignore)
                    .wgexAX(.protection, "killSwitch", label: MacStrings.killSwitch)
                    .accessibilityValue(killSwitch)
                }
                Section {
                    MacControlRow {
                        Toggle(isOn: model.globalSetting(\.lockdown)) {
                            Text(MacStrings.lockdown).lineLimit(1)
                            Text(MacStrings.lockdownNote)
                        }
                        .toggleStyle(.switch).labelsHidden()
                        .wgexControl(.protection, "lockdown", label: MacStrings.lockdown)
                        .disabled(model.hostGuarded || model.busy)
                    } label: {
                        Text(MacStrings.lockdown).lineLimit(1)
                        Text(MacStrings.lockdownNote)
                    }
                    MacControlRow {
                        Toggle(isOn: model.globalSetting(\.allowLAN)) {
                            Text(MacStrings.allowLocalNetwork).lineLimit(1)
                            Text(MacStrings.allowLocalNetworkNote)
                        }
                        .toggleStyle(.switch).labelsHidden()
                        .wgexControl(.protection, "allowLocalNetwork", label: MacStrings.allowLocalNetwork)
                        .disabled(model.hostGuarded || model.busy)
                    } label: {
                        Text(MacStrings.allowLocalNetwork).lineLimit(1)
                        Text(MacStrings.allowLocalNetworkNote)
                    }
                    MacControlRow {
                        Picker(selection: model.globalSetting(\.captiveWindowSeconds)) {
                            Text(MacStrings.text1Minute).lineLimit(1).tag(60)
                            Text(MacStrings.text5Minutes).lineLimit(1).tag(300)
                            Text(MacStrings.text10Minutes).lineLimit(1).tag(600)
                        } label: {
                            Text(MacStrings.signInWindow).lineLimit(1)
                            Text(MacStrings.signInWindowNote)
                        }
                        .labelsHidden().fixedSize()
                        .wgexControl(.settings, "captiveWindow", label: MacStrings.signInWindow)
                        .disabled(model.hostGuarded || model.busy)
                    } label: {
                        Text(MacStrings.signInWindow).lineLimit(1)
                        Text(MacStrings.signInWindowNote)
                    }
                }
                Section(MacStrings.whatWGEXCannotProtect) {
                    Text(MacStrings.limitSignInWindow)
                    Text(MacStrings.limitLocalNetwork)
                    Text(MacStrings.limitBeforeUnlock)
                }
            }
            .formStyle(.macCards(title: model.settingsTab.title))
        }
    }
#endif
