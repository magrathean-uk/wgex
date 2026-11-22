// SPDX-License-Identifier: MIT

import SwiftUI

/// Appearance and accessibility settings a preview renders under.
public struct PreviewTraits: Identifiable, Hashable, Sendable {
    /// Light, standard.
    public static let light = PreviewTraits(id: "Light")
    /// Dark, standard.
    public static let dark = PreviewTraits(id: "Dark", dark: true)
    /// Reduce Motion (cross-fades, cycling dots).
    public static let reduceMotion = PreviewTraits(id: "Reduce Motion", reduceMotion: true)
    /// Reduce Transparency.
    public static let reduceTransparency = PreviewTraits(id: "Reduce Transparency", reduceTransparency: true)
    /// Increase Contrast, light.
    public static let increaseContrast = PreviewTraits(id: "Increase Contrast", increaseContrast: true)
    /// Increase Contrast, dark.
    public static let increaseContrastDark = PreviewTraits(id: "Increase Contrast, dark", dark: true, increaseContrast: true)
    /// Accessibility text size (AX3).
    public static let accessibilityText = PreviewTraits(id: "Accessibility text", accessibilityText: true)

    /// Every preset, in display order.
    public static let all: [PreviewTraits] = [
        .light, .dark, .reduceMotion, .reduceTransparency, .increaseContrast, .increaseContrastDark, .accessibilityText,
    ]

    /// Name, also the identity.
    public let id: String
    /// Dark appearance.
    public var dark = false
    /// Reduce Motion.
    public var reduceMotion = false
    /// Reduce Transparency.
    public var reduceTransparency = false
    /// Increase Contrast.
    public var increaseContrast = false
    /// Accessibility Dynamic Type size.
    public var accessibilityText = false
}

public extension View {
    /// Renders under `traits`, on the system background.
    func previewTraits(_ traits: PreviewTraits) -> some View {
        environment(\.colorScheme, traits.dark ? .dark : .light)
            .environment(\._accessibilityReduceMotion, traits.reduceMotion)
            .environment(\._accessibilityReduceTransparency, traits.reduceTransparency)
            .environment(\._colorSchemeContrast, traits.increaseContrast ? .increased : .standard)
            .dynamicTypeSize(traits.accessibilityText ? .accessibility3 : .large)
            .padding(16)
            .background(traits.dark ? Color.black : Color.white)
    }
}

/// Shows `content` once per trait preset, labelled, for side-by-side review.
public struct PreviewTraitsMatrix<Content: View>: View {
    private let traits: [PreviewTraits]
    private let content: () -> Content

    /// Creates a matrix over `traits` (every preset by default).
    public init(_ traits: [PreviewTraits] = PreviewTraits.all, @ViewBuilder content: @escaping () -> Content) {
        self.traits = traits
        self.content = content
    }

    /// The view body.
    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                ForEach(traits) { trait in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(trait.id)
                            .font(.caption.weight(.semibold))
                        content()
                            .previewTraits(trait)
                    }
                }
            }
            .padding()
        }
    }
}
