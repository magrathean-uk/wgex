// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXUI

/// Every orb state at one size, with the state chip and both text lines.
public struct ConnectionOrbGallery: View {
    private let size: ConnectionOrb.Size

    /// Creates a gallery at `size`.
    public init(size: ConnectionOrb.Size = .compact) {
        self.size = size
    }

    /// The view body.
    public var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: size.diameter + 64), alignment: .top)], spacing: 32) {
            ForEach(PreviewFixtures.presentations) { named in
                VStack(spacing: 12) {
                    ConnectionOrb(presentation: named.presentation, size: size, transportName: "Direct WireGuard") { _ in }
                    StateChip(presentation: named.presentation)
                    Text(named.presentation.primary)
                        .font(Typography.stateTitle)
                        .multilineTextAlignment(.center)
                    Text(named.presentation.secondary)
                        .font(Typography.stateDetail)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
        }
        .environment(\.wgexDisplayDate, PreviewFixtures.referenceDate)
    }
}

/// One orb fed by ``OrbPreviewScenario``: the status stream advances one
/// fake second per real 1.5 s, so the motion plays the same way every time.
public struct AnimatedOrbPreview: View {
    @State private var scenario = OrbPreviewScenario()
    private let size: ConnectionOrb.Size

    /// Creates the preview.
    public init(size: ConnectionOrb.Size = .window) {
        self.size = size
    }

    /// The view body.
    public var body: some View {
        VStack(spacing: 16) {
            ConnectionOrb(presentation: scenario.presentation, size: size, transportName: "Direct WireGuard") { _ in }
            Text(scenario.presentation.primary)
                .font(Typography.stateTitle)
            Text(scenario.presentation.secondary)
                .font(Typography.stateDetail)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .task { await scenario.run() }
    }
}

#Preview("Orb, every state, light") {
    ScrollView { ConnectionOrbGallery().previewTraits(.light) }
}

#Preview("Orb, every state, dark") {
    ScrollView { ConnectionOrbGallery().previewTraits(.dark) }
}

#Preview("Orb, every state, every variant") {
    PreviewTraitsMatrix { ConnectionOrbGallery(size: .menuBar) }
}

#Preview("Orb sizes 96, 160, 220, 320") {
    ScrollView {
        VStack(spacing: 24) {
            ForEach(ConnectionOrb.Size.allCases, id: \.self) { size in
                ConnectionOrb(presentation: PreviewFixtures.presentations[0].presentation, size: size) { _ in }
            }
        }
        .previewTraits(.light)
    }
}

#Preview("Orb, animated") {
    AnimatedOrbPreview().previewTraits(.light)
}

#Preview("Orb, animated, dark") {
    AnimatedOrbPreview().previewTraits(.dark)
}

#Preview("Orb, animated, Reduce Motion") {
    AnimatedOrbPreview().previewTraits(.reduceMotion)
}

#Preview("Orb, animated, Reduce Transparency") {
    AnimatedOrbPreview().previewTraits(.reduceTransparency)
}

#Preview("Orb, animated, Increase Contrast") {
    AnimatedOrbPreview().previewTraits(.increaseContrast)
}

#Preview("Orb, animated, accessibility text") {
    AnimatedOrbPreview(size: .compact).previewTraits(.accessibilityText)
}
