// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI
    import WGEXCore

    /// One System Settings style page per tunnel (SPEC 5.2, 5.3): a status row with Activate or Deactivate, then the
    /// Traffic, Addresses, Server, Protection and Advanced groups, and Edit…, Export… and Delete Tunnel… at the foot.
    package struct MacTunnelPage: View {
        private enum Sheet: String, Identifiable {
            case routes, onDemand, startup, exclusions
            var id: String {
                rawValue
            }
        }

        @Bindable private var model: MacShellModel
        private let profile: TunnelProfile
        private let edit: () -> Void
        private let export: () -> Void
        private let delete: (TunnelProfile) -> Void
        @State private var sheet: Sheet?
        @State private var afterSheet: (() -> Void)?
        @State private var confirmsCaptiveWindow = false

        package init(
            model: MacShellModel, profile: TunnelProfile, edit: @escaping () -> Void, export: @escaping () -> Void,
            delete: @escaping (TunnelProfile) -> Void,
        ) {
            self.model = model; self.profile = profile; self.edit = edit; self.export = export; self.delete = delete
        }

        package var body: some View {
            let page = MacTunnelPagePresentation(model: model, profile: profile)
            Form {
                Section { statusRows(page.status) }
                ForEach(page.groups) { group in
                    Section(group.title) {
                        ForEach(group.rows) { row in rowView(row) }
                        if let note = group.note {
                            Text(note).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                                .fixedSize(horizontal: false, vertical: true)
                                .wgexAX(.main, "exclusionWarning", label: note)
                        }
                    }
                }
                Section {} footer: { foot }
            }
            .formStyle(.macCards(title: page.title))
            .textSelection(.enabled)
            .macCaptiveConfirmation(model: model, isPresented: $confirmsCaptiveWindow)
            .sheet(item: $sheet, onDismiss: runAfterSheet) { sheet in
                switch sheet {
                case .routes: listSheet(MacStrings.routes, page.routes)
                case .exclusions: listSheet(MacStrings.exclusions, page.exclusions, identified: true)
                case .onDemand:
                    MacOnDemandSheet(model: model, profile: profile, edit: { close(then: edit) }, done: { close() })
                case .startup: startupSheet
                }
            }
        }

        // MARK: Status

        @ViewBuilder private func statusRows(_ status: MacTunnelPagePresentation.Status) -> some View {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(status.word).font(.system(size: DesignSheet.TypeScale.body, weight: .semibold)).monospacedDigit().lineLimit(1)
                        .foregroundStyle(status.state == .active ? MacDesign.success : MacDesign.text)
                    if let detail = status.detail {
                        Text(detail).font(MacDesign.caption).foregroundStyle(MacDesign.label2).monospacedDigit()
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let reason = status.reason {
                        Text(reason).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let reporter = status.reporter {
                        Text(reporter).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if model.activeProfileID != profile.id, let blocker = model.activationBlocker(profile) {
                        Text(blocker).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .accessibilityElement(children: .combine)
                .wgexAX(.main, "status", label: [status.word, status.detail].compactMap(\.self).joined(separator: ", "))
                Spacer(minLength: 12)
                Button(status.buttonTitle) { Task { await model.toggleMenuTunnel(profile.id) } }
                    .buttonStyle(MacSheetButtonStyle(status.buttonTitle == MacStrings.activate ? .primary : .secondary))
                    .wgexControl(.main, "action", label: status.buttonTitle)
                    .lineLimit(1)
                    .fixedSize()
                    .disabled(!status.buttonEnabled)
            }
            .padding(.vertical, 4)
            if let extra = status.extra {
                extraRow(extra)
            }
        }

        private func extraRow(_ extra: MacTunnelPagePresentation.Extra) -> some View {
            HStack(spacing: 12) {
                switch extra {
                case let .signIn(note):
                    VStack(alignment: .leading, spacing: 3) {
                        Text(MacStrings.usingHotelWiFi).lineLimit(1)
                        Text(note).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    Button(MacStrings.menuSignIn) { confirmsCaptiveWindow = true }
                        .buttonStyle(.macSecondary)
                        .wgexControl(.main, "openCaptiveWindow", label: MacStrings.menuSignIn)
                        .lineLimit(1).fixedSize()
                        .disabled(model.busy || model.pendingAction != nil)
                case .signInOpen:
                    Text(MacStrings.menuSignInOpen).lineLimit(1)
                    Spacer(minLength: 12)
                    Button(MacStrings.menuEndSignIn) { Task { await model.closeCaptiveWindow() } }
                        .buttonStyle(.macSecondary)
                        .wgexControl(.protection, "endCaptiveWindow", label: MacStrings.menuEndSignIn)
                        .lineLimit(1).fixedSize()
                        .disabled(model.busy)
                case .serviceNotAnswering:
                    Text(MacStrings.menuServiceUnavailable).lineLimit(1)
                    Spacer(minLength: 12)
                    Button(MacStrings.openBackgroundService) { model.windowSelection = .settings(.service) }
                        .buttonStyle(.macSecondary)
                        .wgexControl(.main, "openBackgroundService", label: MacStrings.openBackgroundService)
                        .lineLimit(1).fixedSize()
                }
            }
        }

        // MARK: Rows

        @ViewBuilder private func rowView(_ row: MacTunnelPagePresentation.Row) -> some View {
            if let link = row.link {
                Button { open(link) } label: {
                    HStack(spacing: 6) {
                        Text(row.label).lineLimit(1)
                        Spacer(minLength: 12)
                        value(row).foregroundStyle(MacDesign.textSecondary)
                        Image(systemName: "chevron.right").font(MacDesign.caption.weight(.semibold)).foregroundStyle(MacDesign.label3)
                            .accessibilityHidden(true)
                    }
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .contextMenu { copyButton(row) }
                .wgexControl(.main, "detail", label: row.label, item: row.id)
                .accessibilityValue(row.copyValue)
            } else {
                LabeledContent {
                    value(row)
                } label: {
                    Text(row.label).lineLimit(1)
                }
                .contextMenu { copyButton(row) }
                .accessibilityElement(children: .ignore)
                .wgexAX(.main, "detail", label: row.label, item: row.id)
                .accessibilityValue(row.copyValue)
            }
        }

        private func value(_ row: MacTunnelPagePresentation.Row) -> some View {
            Text(row.value)
                .font(row.monospaced ? MacDesign.body.monospaced() : MacDesign.body)
                .monospacedDigit()
                .lineLimit(1)
                .truncationMode(.middle)
        }

        private func copyButton(_ row: MacTunnelPagePresentation.Row) -> some View {
            Button(MacStrings.copy) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(row.copyValue, forType: .string)
            }
        }

        private func open(_ link: MacTunnelPagePresentation.Link) {
            switch link {
            case .protectionPage: model.windowSelection = .settings(.protection)
            case .routes: sheet = .routes
            case .onDemand: sheet = .onDemand
            case .startup: sheet = .startup
            case .exclusions: sheet = .exclusions
            }
        }

        private var foot: some View {
            HStack {
                Button(MacStrings.editEllipsis, action: edit)
                    .buttonStyle(.macSecondary)
                    .wgexControl(.main, "editProfile", label: MacStrings.editEllipsis)
                    .lineLimit(1).fixedSize()
                Button(MacStrings.export, action: export)
                    .buttonStyle(.macSecondary)
                    .wgexControl(.main, "export", label: MacStrings.export)
                    .lineLimit(1).fixedSize()
                Spacer()
                Button(MacStrings.deleteTunnel, role: .destructive) { delete(profile) }
                    .buttonStyle(.macDestructive)
                    .wgexControl(.main, "deleteTunnel", label: MacStrings.deleteTunnel)
                    .lineLimit(1).fixedSize()
                    .disabled(model.busy)
            }
        }
    }

    private extension MacTunnelPage {
        // MARK: Sheets

        func close(then action: (() -> Void)? = nil) {
            afterSheet = action
            sheet = nil
        }

        func runAfterSheet() {
            let action = afterSheet
            afterSheet = nil
            action?()
        }

        /// The Routes and Exclusions sheets: one copyable line per item. Exclusion lines carry `wgex.main.exclusion`.
        func listSheet(_ title: String, _ items: [String], identified: Bool = false) -> some View {
            VStack(alignment: .leading, spacing: 0) {
                Form {
                    Section(title) {
                        ForEach(items, id: \.self) { item in
                            if identified {
                                Text(item).monospacedDigit().lineLimit(1)
                                    .contextMenu { copyButton(.init("item", title, item)) }
                                    .wgexAX(.main, "exclusion", label: item, item: item)
                            } else {
                                Text(item).monospacedDigit().lineLimit(1)
                                    .contextMenu { copyButton(.init("item", title, item)) }
                            }
                        }
                    }
                }
                .formStyle(.macCards)
                .textSelection(.enabled)
                sheetFoot
            }
            .frame(width: 420, height: 420)
            .background(MacDesign.pageBackground)
        }

        var startupSheet: some View {
            VStack(alignment: .leading, spacing: 0) {
                Form {
                    Section {
                        Picker(MacStrings.connectAutomatically, selection: startup) {
                            ForEach(MacStartupOption.allCases) { option in
                                Text(option.pageWord).lineLimit(1).tag(option)
                            }
                        }
                        .pickerStyle(.radioGroup)
                        .foregroundStyle(MacDesign.text)
                        .disabled(model.busy || model.hostGuarded)
                        .wgexControl(.main, "startupOption", label: MacStrings.connectAutomatically)
                    } footer: {
                        Text(MacStrings.startupNote).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                    }
                }
                .formStyle(.macCards)
                .frame(minHeight: 200)
                sheetFoot
            }
            .frame(width: 420)
            .background(MacDesign.pageBackground)
        }

        var sheetFoot: some View {
            HStack {
                Spacer()
                Button(MacStrings.done) { close() }
                    .buttonStyle(.macPrimary)
                    .wgexControl(.main, "sheetDone", label: MacStrings.done)
                    .keyboardShortcut(.defaultAction)
                    .lineLimit(1)
            }
            .padding([.horizontal, .bottom], 16)
        }

        /// Saves for the selected tunnel, which is this page's tunnel (`saveStartup` acts on the selection).
        var startup: Binding<MacStartupOption> {
            Binding(
                get: { MacStartupOption(options: model.profiles.first { $0.id == profile.id }?.macOptions ?? profile.macOptions) },
                set: { option in
                    guard model.selectedProfileID == profile.id else { return }
                    Task { await model.saveStartup(option) }
                },
            )
        }
    }
#endif
