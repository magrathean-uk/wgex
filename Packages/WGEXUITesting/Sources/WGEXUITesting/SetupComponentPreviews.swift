// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore
import WGEXUI

/// Onboarding and service components in every state.
public struct SetupComponentsGallery: View {
    /// Creates the gallery.
    public init() {}

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            ForEach(ServiceState.allCases, id: \.self) { state in
                ServiceStateCard(state: state, daemonRunning: false) {}
            }
            ServiceStateCard(state: .enabled, daemonRunning: true) {}
            ForEach(SecureInstallState.all, id: \.self) { state in
                SecureInstallCard(state: state) {}
            }
            OnboardingStep(
                title: "Approve the service",
                message: "WGEX needs a background service to run the tunnel and enforce protection when this app is closed.",
                index: 3,
                count: 7,
                primary: OnboardingAction("Continue") {},
                secondary: OnboardingAction("Not now") {},
            ) {
                ServiceStateCard(state: .requiresApproval, daemonRunning: false) {}
            }
            .frame(minHeight: 520)
        }
    }
}

#Preview("Setup components, light") {
    ScrollView { SetupComponentsGallery().previewTraits(.light) }
}

#Preview("Setup components, dark") {
    ScrollView { SetupComponentsGallery().previewTraits(.dark) }
}

#Preview("Setup components, every variant") {
    PreviewTraitsMatrix { SetupComponentsGallery() }
}

#Preview("Service, first registration") {
    ServiceStateCard(state: .notRegistered, daemonRunning: false) {}.padding()
}

#Preview("Service, launchd plist missing") {
    ServiceStateCard(state: .notFound, daemonRunning: false) {}.padding()
}

#Preview("Service, registered awaiting approval") {
    ServiceStateCard(state: .requiresApproval, daemonRunning: false) {}.padding()
}
