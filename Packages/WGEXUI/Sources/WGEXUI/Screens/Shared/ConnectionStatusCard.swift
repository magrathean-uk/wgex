// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// Status composition shared by app shells, with measurements unavailable until sampled.
public struct ConnectionStatusCard: View {
    private let name: String
    private let presentation: ProtectionPresentation
    private let relayEnabled: Bool
    private let action: () -> Void
    private let onTransportPicker: () -> Void
    @Environment(\.dynamicTypeSize) private var typeSize

    public init(
        name: String,
        presentation: ProtectionPresentation,
        relayEnabled: Bool,
        onTransportPicker: @escaping () -> Void = {},
        action: @escaping () -> Void,
    ) {
        self.name = name
        self.presentation = presentation
        self.relayEnabled = relayEnabled
        self.action = action
        self.onTransportPicker = onTransportPicker
    }

    public var body: some View {
        VStack(spacing: Spacing.large) {
            ConnectionOrb(
                presentation: presentation,
                transportName: relayEnabled ? "Direct WireGuard" : nil,
                transportPickerEnabled: relayEnabled,
                onToggle: { _ in action() },
                onTransportPicker: onTransportPicker,
            )
            Text(name).font(.title2.bold()).multilineTextAlignment(.center)
            Text(presentation.primary).font(.title2.bold()).wgexAX(.connection, "verdict", label: presentation.primary)
            Text(presentation.secondary).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button(presentation.action.title, action: action)
                .buttonStyle(.glassProminent).controlSize(.large).wgexControl(.connection, "action", label: presentation.action.title)
            StateChip(presentation: presentation)
            statistics
            Text("Last 30 seconds").font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    private var statistics: some View {
        let layout = typeSize >= .xxxLarge ? AnyLayout(VStackLayout(spacing: Spacing.large)) :
            AnyLayout(HStackLayout(spacing: Spacing.medium))
        return layout {
            StatTile(title: "Last handshake", value: .unavailable)
            rate("Download")
            rate("Upload")
        }
    }

    private func rate(_ title: String) -> some View {
        VStack(alignment: .leading) {
            StatTile(title: title, value: .unavailable)
            Sparkline(title: title, series: SparklineSeries(), now: Date())
                .hidden()
                .overlay(alignment: .leading) { Text("No sample").font(.caption).foregroundStyle(.secondary) }
        }
    }
}
