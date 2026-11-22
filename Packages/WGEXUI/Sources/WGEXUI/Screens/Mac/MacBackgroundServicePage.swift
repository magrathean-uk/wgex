// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// Background Service (SPEC 8.3): three facts, Open Login Items Settings… and Register Again, then Uninstall on its
    /// own at the foot. The uninstall flow itself is the existing sheet.
    package struct MacBackgroundServicePage: View {
        @Bindable private var model: MacShellModel
        private let simulateApproval: () -> Void
        @State private var presentsUninstall = false

        package init(model: MacShellModel, simulateApproval: @escaping () -> Void = {}) {
            self.model = model
            self.simulateApproval = simulateApproval
        }

        package var body: some View {
            let facts = MacAppPagesPresentation.serviceFacts(
                state: model.serviceState, running: model.daemonRunning, install: model.secureInstall,
            )
            Form {
                Section {
                    ForEach(facts) { fact in factRow(fact) }
                }
                Section { actions }
                if model.downgradeDetected {
                    Section {
                        LabeledContent {
                            Text(MacStrings.downgradeDetected).lineLimit(1).fixedSize()
                        } label: {
                            Text(MacStrings.downgradeState).lineLimit(1)
                            Text(UserStrings.downgradeDetected)
                        }
                        .accessibilityIdentifier("wgex.settings.downgradeState") // M04-T20: keep the native label
                    }
                }
                uninstallSection
            }
            .formStyle(.macCards(title: MacSettingsTab.service.title))
            .sheet(isPresented: $presentsUninstall) { MacUninstallSheet(uninstall: model.uninstall) }
        }

        /// Uninstall on its own at the foot, as Delete sits in System Settings (SPEC 8.3, D11).
        private var uninstallSection: some View {
            Section {
                Button(role: .destructive) { presentsUninstall = true } label: {
                    Text(MacStrings.uninstallWGEXEllipsis).lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .contentShape(.rect)
                }
                .buttonStyle(.macDestructive)
                .wgexControl(.service, "uninstallOpen", label: MacStrings.uninstallWGEXEllipsis)
                .disabled(model.hostGuarded)
            } header: {
                Text(MacStrings.uninstallGroup)
            } footer: {
                Text(MacStrings.uninstallFootnote).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
            }
        }

        private func factRow(_ fact: MacAppPagesPresentation.Fact) -> some View {
            LabeledContent {
                HStack(spacing: 12) {
                    if let action = fact.action {
                        Button(action) { Task { await model.verifySecureInstall() } }
                            .buttonStyle(.macSecondary)
                            .wgexControl(.service, "actionTitle", label: action)
                            .disabled(model.hostGuarded || model.busy)
                            .lineLimit(1).fixedSize()
                    }
                    Text(fact.value).foregroundStyle(MacDesign.textSecondary).monospacedDigit().lineLimit(1).fixedSize()
                        .wgexAX(.service, "fact", label: fact.label, item: fact.id)
                        .accessibilityValue(fact.value)
                }
            } label: {
                Text(fact.label).lineLimit(1)
                if let detail = fact.detail {
                    Text(detail)
                }
            }
        }

        private var actions: some View {
            HStack {
                Button(MacStrings.openLoginItemsSettings, action: model.openApproval)
                    .buttonStyle(.macSecondary)
                    .wgexControl(.service, "openSystemSettings", label: MacStrings.openLoginItemsSettings)
                    .lineLimit(1).fixedSize()
                Button(MacStrings.registerAgain, action: registerAgain)
                    .buttonStyle(.macSecondary)
                    .wgexControl(.settings, "reRegisterBackgroundService", label: MacStrings.registerAgain)
                    .disabled(model.hostGuarded || model.busy)
                    .lineLimit(1).fixedSize()
                if model.updateAvailable {
                    Button(MacStrings.finishUpdateEllipsis) { Task { await model.finishUpdate() } }
                        .buttonStyle(.macPrimary)
                        .wgexControl(.service, "finishUpdate", label: MacStrings.finishUpdateEllipsis)
                        .disabled(model.hostGuarded || model.busy)
                        .lineLimit(1).fixedSize()
                }
                if model.simulated, model.serviceState == .requiresApproval {
                    Button(MacStrings.simulateApproval, action: simulateApproval)
                        .buttonStyle(.macSecondary)
                        .wgexControl(.onboarding, "simulateApproval", label: MacStrings.simulateApproval)
                        .lineLimit(1).fixedSize()
                }
                Spacer(minLength: 0)
            }
        }

        private func registerAgain() {
            Task {
                switch MacAppPagesPresentation.registerAgain(for: model.serviceState) {
                case .register: await model.registerService()
                case .reregister: await model.reregisterService()
                }
            }
        }
    }
#endif
