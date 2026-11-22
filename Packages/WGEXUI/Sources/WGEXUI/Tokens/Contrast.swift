// SPDX-License-Identifier: MIT

import Foundation
import SwiftUI

/// An sRGB colour with gamma-encoded components in 0...1, used for WCAG
/// contrast checks (P0-13). Mirrors `Tools/design/contrast.swift`.
public nonisolated struct ContrastColour: Sendable, Hashable {
    /// Opaque white.
    public static let white = ContrastColour(red: 1, green: 1, blue: 1)
    /// Opaque black.
    public static let black = ContrastColour(red: 0, green: 0, blue: 0)

    /// Red component.
    public var red: Double
    /// Green component.
    public var green: Double
    /// Blue component.
    public var blue: Double
    /// Opacity.
    public var opacity: Double

    /// Creates a colour.
    public init(red: Double, green: Double, blue: Double, opacity: Double = 1) {
        self.red = red
        self.green = green
        self.blue = blue
        self.opacity = opacity
    }

    /// WCAG 2.x relative luminance of the opaque colour.
    public var relativeLuminance: Double {
        0.2126 * Self.linear(red) + 0.7152 * Self.linear(green) + 0.0722 * Self.linear(blue)
    }

    /// Hex text such as `#34C759`, with the opacity appended when below 1.
    public var hex: String {
        let digits = [red, green, blue].map { String(format: "%02X", Int(($0 * 255).rounded())) }.joined()
        return opacity < 1 ? "#\(digits) @\(String(format: "%.2f", opacity))" : "#\(digits)"
    }

    /// Source-over composite of this colour on an opaque `background`.
    public func composited(over background: ContrastColour) -> ContrastColour {
        let alpha = min(max(opacity, 0), 1)
        return ContrastColour(
            red: red * alpha + background.red * (1 - alpha),
            green: green * alpha + background.green * (1 - alpha),
            blue: blue * alpha + background.blue * (1 - alpha),
        )
    }

    /// WCAG contrast ratio between two opaque colours, 1...21.
    public static func ratio(_ first: ContrastColour, _ second: ContrastColour) -> Double {
        let lighter = max(first.relativeLuminance, second.relativeLuminance)
        let darker = min(first.relativeLuminance, second.relativeLuminance)
        return (lighter + 0.05) / (darker + 0.05)
    }

    private static func linear(_ component: Double) -> Double {
        component <= 0.040_45 ? component / 12.92 : pow((component + 0.055) / 1.055, 2.4)
    }
}

/// The four appearances the contrast gate covers.
public nonisolated enum ContrastAppearance: String, CaseIterable, Sendable, Hashable {
    /// Light, standard contrast.
    case light
    /// Dark, standard contrast.
    case dark
    /// Light with Increase Contrast.
    case lightIncreased
    /// Dark with Increase Contrast.
    case darkIncreased

    /// Minimum ratio for text on a state colour (WCAG AA body text).
    public static let minimumRatio = 4.5

    /// Opaque content background the fill sits on (system background).
    public var background: ContrastColour {
        isDark ? .black : .white
    }

    /// Whether the appearance is dark.
    public var isDark: Bool {
        self == .dark || self == .darkIncreased
    }

    /// Whether Increase Contrast is on.
    public var isIncreased: Bool {
        self == .lightIncreased || self == .darkIncreased
    }

    /// Environment values that select this appearance.
    public var environment: EnvironmentValues {
        var values = EnvironmentValues()
        values.colorScheme = isDark ? .dark : .light
        values._colorSchemeContrast = isIncreased ? .increased : .standard
        return values
    }
}

/// One row of the text-on-state-colour contrast table.
public nonisolated struct ContrastResult: Sendable, Hashable {
    /// Token checked.
    public var token: StateColor
    /// Appearance checked.
    public var appearance: ContrastAppearance
    /// Fill composited on the background.
    public var fill: ContrastColour
    /// Text colour composited on the fill.
    public var text: ContrastColour
    /// Contrast ratio of text on fill.
    public var ratio: Double

    /// Whether the ratio meets ``ContrastAppearance/minimumRatio``.
    public var passes: Bool {
        ratio >= ContrastAppearance.minimumRatio
    }
}

public extension StateColor {
    /// Resolves the fill and foreground for `appearance` on this platform and
    /// returns the contrast of text on the fill.
    func contrast(in appearance: ContrastAppearance) -> ContrastResult {
        let environment = appearance.environment
        let fill = Self.contrastColour(color.resolve(in: environment)).composited(over: appearance.background)
        let text = Self.contrastColour(foreground.resolve(in: environment)).composited(over: fill)
        return ContrastResult(token: self, appearance: appearance, fill: fill, text: text, ratio: ContrastColour.ratio(text, fill))
    }

    private static func contrastColour(_ resolved: Color.Resolved) -> ContrastColour {
        ContrastColour(
            red: Double(resolved.red),
            green: Double(resolved.green),
            blue: Double(resolved.blue),
            opacity: Double(resolved.opacity),
        )
    }
}
