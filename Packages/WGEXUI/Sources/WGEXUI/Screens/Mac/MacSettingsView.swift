// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// The app pages in the main window (SPEC 8): one page per sidebar destination. The Log fills its page outside any
    /// form; the legacy Network destination shows Protection, which now holds Allow local network.
    public struct MacSettingsView: View {
        @Bindable private var model: MacShellModel
        private let acknowledgements: String
        private let simulateApproval: () -> Void

        /// `revisit` is kept for existing call sites; no page offers Revisit setup any more (SPEC 9).
        public init(
            model: MacShellModel,
            acknowledgements: String = MacStrings.acknowledgementsCouldNotBeLoaded,
            revisit _: @escaping (MacOnboardingStep) -> Void = { _ in },
            simulateApproval: @escaping () -> Void = {},
        ) {
            self.model = model
            self.acknowledgements = acknowledgements
            self.simulateApproval = simulateApproval
        }

        public var body: some View {
            content(model.settingsTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .focusSection()
                .accessibilityElement(children: .contain)
                .wgexAX(.settings, "surface", label: model.settingsTab.title)
        }

        @ViewBuilder private func content(_ tab: MacSettingsTab) -> some View {
            switch tab {
            case .general: MacGeneralPage(model: model)
            case .protection, .network: MacProtectionPage(model: model)
            case .service: MacBackgroundServicePage(model: model, simulateApproval: simulateApproval)
            case .diagnostics: MacLogPage(model: model)
            case .about: MacAboutPage(acknowledgements: acknowledgements)
            }
        }
    }
#endif
