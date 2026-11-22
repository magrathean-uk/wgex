// SPDX-License-Identifier: MIT

import SwiftUI

/// Semantic state colours (plan 06 §2). Fills are system semantic colours so
/// Increase Contrast and vibrancy track the platform; text and glyphs drawn on
/// a fill use ``foreground``, which comes from the package asset catalogue only
/// where `Tools/design/contrast.swift` found the default below 4.5:1.
public nonisolated enum StateColor: String, CaseIterable, Sendable, Hashable {
    /// Traffic flows through a verified tunnel.
    case protected
    /// Traffic outside the tunnel is blocked.
    case blocked
    /// Traffic can leave outside the tunnel.
    case unprotected
    /// Nothing can be claimed; also every stale presentation.
    case unknown
    /// Transport and in-progress activity; never a protection claim.
    case transport

    /// Default foreground on a state fill.
    public static let defaultForeground = Color.black

    /// Whether the token claims a protection outcome (green, orange or red).
    public var isProtectionColour: Bool {
        switch self {
        case .protected, .blocked, .unprotected:
            true
        case .unknown, .transport:
            false
        }
    }

    /// The fill: `.green`, `.orange`, `.red`, `.secondary` or `.blue`.
    public var color: Color {
        switch self {
        case .protected: .green
        case .blocked: .orange
        case .unprotected: .red
        case .unknown: .secondary
        case .transport: .blue
        }
    }

    /// Semantic tint adjusted towards the system label for readable plain text.
    /// Rings retain the original system colour; small labels need 4.5:1 contrast.
    public func labelColor(for scheme: ColorScheme) -> Color {
        if self == .unknown {
            #if os(macOS)
                return MacDesign.label2
            #else
                return .secondary
            #endif
        }
        return color.mix(with: .primary, by: scheme == .light ? 0.5 : 0.3)
    }

    /// Name of the asset-catalogue colour set that overrides ``foreground``, if any.
    public var foregroundOverrideName: String? {
        switch self {
        case .unknown:
            "StateUnknownForeground"
        case .protected, .blocked, .unprotected, .transport:
            nil
        }
    }

    /// Text and glyph colour on a ``color`` fill.
    public var foreground: Color {
        if let name = foregroundOverrideName {
            Color(name, bundle: .module)
        } else {
            Self.defaultForeground
        }
    }

    /// Spoken and written name of the colour's meaning, never used on its own.
    public var meaning: String {
        switch self {
        case .protected: "Protected"
        case .blocked: "Blocked"
        case .unprotected: "Unprotected"
        case .unknown: "Unknown"
        case .transport: "Transport"
        }
    }
}
