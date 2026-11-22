// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// Confirms deleting the tunnel in `pending` in a standard alert (SPEC 6.4); the sidebar context menu and the tunnel page
    /// set it. For the active tunnel the alert says it is deactivated first, and the shell does so before deleting.
    package struct MacDeleteTunnelAlert: ViewModifier {
        package let model: MacShellModel
        @Binding package var pending: TunnelProfile?

        package func body(content: Content) -> some View {
            content.alert(
                pending.map { MacStrings.deleteTunnelTitle($0.name) } ?? "",
                isPresented: Binding(get: { pending != nil }, set: {
                    if !$0 {
                        pending = nil
                    }
                }),
                presenting: pending,
            ) { profile in
                Button(MacStrings.deleteAction, role: .destructive) {
                    Task { await model.deleteProfile(profile) }
                    pending = nil
                }.wgexControl(.main, "confirmDelete", label: MacStrings.deleteAction)
                Button(MacStrings.cancel, role: .cancel) { pending = nil }
                    .wgexControl(.main, "cancelDelete", label: MacStrings.cancel)
            } message: { profile in
                Text(Self.message(profile, deactivatesFirst: model.deletionDeactivatesFirst(profile)))
            }
        }

        /// "This cannot be undone.", followed for the active tunnel by "<name> is active. It will be deactivated first."
        package static func message(_ profile: TunnelProfile, deactivatesFirst: Bool) -> String {
            deactivatesFirst ? MacStrings.deleteCannotBeUndone + " " + MacStrings.tunnelWillBeDeactivatedFirst(profile.name)
                : MacStrings.deleteCannotBeUndone
        }
    }

    package extension View {
        /// Attach once to the main window so every delete entry point shares one confirmation.
        func macDeleteTunnelAlert(model: MacShellModel, pending: Binding<TunnelProfile?>) -> some View {
            modifier(MacDeleteTunnelAlert(model: model, pending: pending))
        }
    }
#endif
