// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// The tunnel page's Connect on demand sheet: the only place that arms and disarms (ADR-030 rule 1 as the menu does),
    /// the daemon's state for this tunnel in words, the rule summary, and Edit… for the rules, which live in the editor.
    package struct MacOnDemandSheet: View {
        @Bindable private var model: MacShellModel
        private let profile: TunnelProfile
        private let edit: () -> Void
        private let done: () -> Void

        package init(model: MacShellModel, profile: TunnelProfile, edit: @escaping () -> Void, done: @escaping () -> Void) {
            self.model = model; self.profile = profile; self.edit = edit; self.done = done
        }

        package var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                Form {
                    Section {
                        LabeledContent(MacStrings.connectOnDemand) {
                            Text(MacTunnelPagePresentation.onDemandSummary(profile.onDemand)).lineLimit(1)
                        }
                        if let state = model.onDemandPresentation(for: profile) {
                            MacControlRow {
                                Toggle(isOn: armed) {
                                    Text(state.title).lineLimit(1)
                                    if let detail = state.detail {
                                        Text(detail)
                                    }
                                }
                                .toggleStyle(.switch).labelsHidden()
                                .disabled(!model.canToggleOnDemand(profile))
                                .wgexControl(
                                    .main, "onDemandToggle", label: MacStrings.onDemandToggleLabel(profile.name),
                                    item: profile.id.uuidString, inputLabel: MacStrings.onDemandToggle,
                                )
                            } label: {
                                Text(state.title).lineLimit(1)
                                if let detail = state.detail {
                                    Text(detail)
                                }
                            }
                        }
                    }
                }
                .formStyle(.macCards)
                .frame(minHeight: 120)
                HStack {
                    Button(MacStrings.editEllipsis, action: edit)
                        .wgexControl(.main, "onDemandEdit", label: MacStrings.editEllipsis)
                        .lineLimit(1)
                    Spacer()
                    Button(MacStrings.done, action: done)
                        .wgexControl(.main, "sheetDone", label: MacStrings.done)
                        .buttonStyle(.macPrimary)
                        .keyboardShortcut(.defaultAction)
                        .lineLimit(1)
                }
                .padding([.horizontal, .bottom], 16)
            }
            .buttonStyle(.macSecondary)
            .frame(width: 460)
            .background(MacDesign.pageBackground)
        }

        private var armed: Binding<Bool> {
            Binding(
                get: { model.isOnDemandArmed(profile.id) },
                set: { value in Task { await model.setOnDemand(value, for: profile) } },
            )
        }
    }
#endif
