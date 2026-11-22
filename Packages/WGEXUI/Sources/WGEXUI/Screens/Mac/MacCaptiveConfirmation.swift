// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// One consent sheet for every entry point that lowers protection for network sign-in.
    package struct MacCaptiveConfirmation: ViewModifier {
        @Bindable package var model: MacShellModel
        @Binding package var isPresented: Bool

        package func body(content: Content) -> some View {
            content
                .sheet(isPresented: $isPresented) { confirmation }
                .onChange(of: model.showsCaptiveButton) { _, _ in isPresented = false }
        }

        private var confirmation: some View {
            VStack(alignment: .leading, spacing: 16) {
                Text(MacStrings.confirmOpenCaptiveWindow).font(MacDesign.heading)
                Text(MacStrings.unprotectedWebTrafficIsAllowed).fixedSize(horizontal: false, vertical: true)
                Text(CaptiveWindowCopy.message(remaining: Double(model.preferences.global.captiveWindowSeconds)))
                HStack {
                    Button(MacStrings.cancel) { isPresented = false }
                        .wgexControl(.protection, "cancelCaptiveWindow", label: MacStrings.cancel)
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button(MacStrings.confirmOpenCaptiveWindow) {
                        isPresented = false
                        Task { await model.openCaptiveWindow() }
                    }.wgexControl(.protection, "confirmCaptiveWindow", label: MacStrings.confirmOpenCaptiveWindow)
                        .disabled(model.busy || !model.showsCaptiveButton)
                }
            }
            .buttonStyle(.macSecondary)
            .padding(24).frame(width: 420)
            .background(MacDesign.pageBackground)
        }
    }

    package extension View {
        /// Attach to a stable container so the sheet survives removal of its conditional entry button.
        func macCaptiveConfirmation(model: MacShellModel, isPresented: Binding<Bool>) -> some View {
            modifier(MacCaptiveConfirmation(model: model, isPresented: isPresented))
        }
    }
#endif
