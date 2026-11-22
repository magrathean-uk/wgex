// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI

    /// Confirmation, progress, failure with retry, and the final screen of the uninstall (M05-T10).
    package struct MacUninstallSheet: View {
        @Environment(\.dismiss) private var dismiss
        @Bindable private var uninstall: MacUninstall

        package init(uninstall: MacUninstall) {
            self.uninstall = uninstall
        }

        package var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                if uninstall.phase == .finished {
                    finished
                } else {
                    confirmation
                }
            }
            .buttonStyle(.macSecondary)
            .padding(20).frame(width: 460)
            .background(MacDesign.pageBackground)
            .interactiveDismissDisabled(uninstall.isWorking || uninstall.phase == .finished)
        }

        @ViewBuilder private var confirmation: some View {
            Text(uninstall.finishing ? MacStrings.finishUninstallingWGEX : MacStrings.uninstallWGEXQuestion)
                .font(MacDesign.heading)
            if uninstall.finishing {
                Text(uninstall.needsAdministrator ? MacStrings.finishUninstallResumeExplanation : MacStrings.finishUninstallExplanation)
            } else {
                Text(MacStrings.uninstallEffects)
                Text(MacStrings.uninstallKeepsProfiles).foregroundStyle(MacDesign.label2)
                Toggle(MacStrings.alsoRemoveProfilesAndSettings, isOn: $uninstall.removeProfilesAndSettings)
                    .wgexControl(.service, "uninstallPurge", label: MacStrings.alsoRemoveProfilesAndSettings)
                    .disabled(!uninstall.canChoosePurge)
            }
            if uninstall.isWorking {
                ProgressView(MacStrings.uninstalling).controlSize(.small)
            }
            if case let .failed(message) = uninstall.phase {
                Text(message).foregroundStyle(MacDesign.error).wgexAX(.service, "uninstallError", label: message)
            }
            HStack {
                Spacer()
                Button(uninstall.finishing ? MacStrings.notNow : MacStrings.cancel) {
                    uninstall.dismissOffer()
                    dismiss()
                }
                .wgexControl(.service, "uninstallCancel", label: MacStrings.cancel)
                .keyboardShortcut(.cancelAction)
                .disabled(uninstall.isWorking)
                if isRetry {
                    primaryButton.wgexControl(.service, "uninstallRetry", label: MacStrings.tryAgain)
                } else {
                    primaryButton.wgexControl(.service, "uninstallConfirm", label: primaryTitle)
                }
            }
        }

        @ViewBuilder private var finished: some View {
            Text(MacStrings.wgexIsUninstalled).font(MacDesign.heading)
            Text(MacStrings.wgexCanBeMovedToTheBin)
            HStack {
                Spacer()
                Button(MacStrings.quitWGEX) { uninstall.quit(dismissSheet: { dismiss() }) }
                    .wgexControl(.service, "uninstallQuit", label: MacStrings.quitWGEX)
                    .buttonStyle(.macPrimary)
                    .keyboardShortcut(.defaultAction)
            }
        }

        private var primaryButton: some View {
            Button(primaryTitle) { Task { await uninstall.run() } }
                .buttonStyle(.macPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(uninstall.isWorking)
        }

        private var isRetry: Bool {
            if case .failed = uninstall.phase {
                return true
            }
            return false
        }

        private var primaryTitle: String {
            if isRetry {
                return MacStrings.tryAgain
            }
            return uninstall.finishing ? MacStrings.finishUninstall : MacStrings.uninstallEllipsis
        }
    }

    package extension View {
        /// The main window's offer to finish an uninstall the daemon already holds (started from the CLI).
        func macUninstallOffer(_ uninstall: MacUninstall) -> some View {
            sheet(isPresented: Bindable(uninstall).finishOffered) { MacUninstallSheet(uninstall: uninstall) }
        }
    }
#endif
