// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// Release-visible feature flag section, reusable by each app shell.
public struct TransportSettingsSection: View {
    @Binding private var flags: FeatureFlags

    public init(flags: Binding<FeatureFlags>) {
        _flags = flags
    }

    public var body: some View {
        Section(MacStrings.transports) {
            Toggle(MacStrings.experimentalRelayTransports, isOn: $flags.relayTransports).wgexControl(
                .settings,
                "experimentalRelayTransports",
                label: MacStrings.experimentalRelayTransports,
            )
            Text(MacStrings.relayTransportsAreExperimental)
                .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

public struct AboutSettingsSection: View {
    public init() {}

    public var body: some View {
        Section(MacStrings.about) {
            LabeledContent("WGEX", value: MacStrings.openSourceWireGuardClient).wgexAX(.settings, "app", label: "WGEX")
            NavigationLink(MacStrings.acknowledgements) {
                List {
                    Text(MacStrings.wGEXIsMITLicensedItUsesWire)
                    LabeledContent("wireguard-apple", value: MacStrings.wireGuardLicence).wgexAX(
                        .settings,
                        "wireguardapple",
                        label: "wireguard-apple",
                    )
                    LabeledContent("wombat-vpn", value: MacStrings.wombatLicence).wgexAX(.settings, "wombatvpn", label: "wombat-vpn")
                    LabeledContent(MacStrings.firezoneSwiftComponents, value: MacStrings.firezoneLicence).wgexAX(
                        .settings,
                        "firezoneSwiftComponents",
                        label: MacStrings.firezoneSwiftComponents,
                    )
                    Text(MacStrings.thirdPartyLicenceNoticesAre)
                }.navigationTitle(MacStrings.acknowledgements)
            }
            Text(
                MacStrings.wireGuardIsARegistered,
            )
            .font(.footnote)
        }
    }
}
