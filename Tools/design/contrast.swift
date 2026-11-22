#!/usr/bin/env swift
// SPDX-License-Identifier: MIT
// Text-on-state-colour contrast gate (tickets P0-13, P5-01; plan 06 §2).
//
// Resolves the WGEX state fills (system semantic colours) with SwiftUI for
// light, dark and both Increase Contrast appearances, composites each fill on
// the opaque system background (white or black), and checks the text colour
// drawn on it against WCAG 2.x 4.5:1. The default text colour is black; an
// asset-catalogue colour set named State<Token>Foreground in the WGEXUI
// package overrides it. The table shows the default ratio (which decided
// whether an override was needed) and the effective ratio (which must pass).
//
// Usage: swift Tools/design/contrast.swift [--catalogue <Colors.xcassets>]
// Exit status: 0 when every effective ratio is at least 4.5:1, 1 otherwise,
// 2 on a usage or catalogue error. No dependencies beyond the macOS SDK.
import Foundation
import SwiftUI

private struct RGB {
    var red, green, blue, alpha: Double

    var luminance: Double {
        func linear(_ c: Double) -> Double {
            c <= 0.04045 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
    }

    var hex: String {
        let digits = [red, green, blue].map { String(format: "%02X", Int(($0 * 255).rounded())) }.joined()
        return alpha < 1 ? "#\(digits)@\(String(format: "%.2f", alpha))" : "#\(digits)"
    }

    func over(_ background: RGB) -> RGB {
        RGB(
            red: red * alpha + background.red * (1 - alpha),
            green: green * alpha + background.green * (1 - alpha),
            blue: blue * alpha + background.blue * (1 - alpha),
            alpha: 1,
        )
    }

    static func ratio(_ a: RGB, _ b: RGB) -> Double {
        let (hi, lo) = (max(a.luminance, b.luminance), min(a.luminance, b.luminance))
        return (hi + 0.05) / (lo + 0.05)
    }

    static let white = RGB(red: 1, green: 1, blue: 1, alpha: 1)
    static let black = RGB(red: 0, green: 0, blue: 0, alpha: 1)
}

private struct Appearance {
    let name: String
    let dark: Bool
    let increased: Bool
}

private let appearances = [
    Appearance(name: "light", dark: false, increased: false),
    Appearance(name: "dark", dark: true, increased: false),
    Appearance(name: "light, increased contrast", dark: false, increased: true),
    Appearance(name: "dark, increased contrast", dark: true, increased: true),
]

/// Token name, fill, as in WGEXUI/Tokens/StateColor.swift.
private let tokens: [(String, Color)] = [
    ("protected", .green), ("blocked", .orange), ("unprotected", .red), ("unknown", .secondary), ("transport", .blue),
]
private let minimum = 4.5

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("contrast: \(message)\n".utf8))
    exit(2)
}

private var catalogue = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Packages/WGEXUI/Sources/WGEXUI/Resources/Colors.xcassets")
private var arguments = CommandLine.arguments.dropFirst()
while let argument = arguments.popFirst() {
    guard argument == "--catalogue", let path = arguments.popFirst() else { fail("usage: contrast.swift [--catalogue <Colors.xcassets>]") }
    catalogue = URL(fileURLWithPath: path)
}

/// Parses one component: "0.5", "0x80" or "128".
private func component(_ value: Any?) -> Double? {
    guard let text = value as? String else { return nil }
    if text.hasPrefix("0x"), let byte = Int(text.dropFirst(2), radix: 16) {
        return Double(byte) / 255
    }
    if text.contains("."), let number = Double(text) {
        return number
    }
    return Int(text).map { Double($0) / 255 }
}

/// The colour-set entry Xcode would pick for an appearance.
private func overrideColour(token: String, appearance: Appearance) -> RGB? {
    let name = "State\(token.prefix(1).uppercased())\(token.dropFirst())Foreground.colorset"
    let url = catalogue.appendingPathComponent(name).appendingPathComponent("Contents.json")
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    guard let data = try? Data(contentsOf: url),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let entries = json["colors"] as? [[String: Any]]
    else { fail("cannot read \(url.path)") }
    func traits(_ entry: [String: Any]) -> (dark: Bool, high: Bool) {
        let list = entry["appearances"] as? [[String: String]] ?? []
        return (list.contains { $0["value"] == "dark" }, list.contains { $0["value"] == "high" })
    }
    let preferences: [(Bool, Bool)] = [
        (appearance.dark, appearance.increased), (appearance.dark, false), (false, appearance.increased), (false, false),
    ]
    for (dark, high) in preferences {
        if let entry = entries.first(where: { traits($0) == (dark, high) }),
           let color = entry["color"] as? [String: Any], let parts = color["components"] as? [String: Any],
           let red = component(parts["red"]), let green = component(parts["green"]), let blue = component(parts["blue"])
        {
            return RGB(red: red, green: green, blue: blue, alpha: component(parts["alpha"]) ?? 1)
        }
    }
    fail("\(name) has no usable entry")
}

private func resolve(_ color: Color, _ appearance: Appearance) -> RGB {
    var environment = EnvironmentValues()
    environment.colorScheme = appearance.dark ? .dark : .light
    environment._colorSchemeContrast = appearance.increased ? .increased : .standard
    let resolved = color.resolve(in: environment)
    return RGB(red: Double(resolved.red), green: Double(resolved.green), blue: Double(resolved.blue), alpha: Double(resolved.opacity))
}

private let failures = MainActor.assumeIsolated { () -> Int in
    var failures = 0
    print("| Token | Appearance | Fill on background | Default text | Default ratio | Override | Effective ratio | Result |")
    print("|---|---|---|---|---|---|---|---|")
    for (token, color) in tokens {
        for appearance in appearances {
            let background = appearance.dark ? RGB.black : RGB.white
            let fill = resolve(color, appearance).over(background)
            let defaultRatio = RGB.ratio(RGB.black, fill)
            let override = overrideColour(token: token, appearance: appearance)
            let effective = RGB.ratio((override ?? RGB.black).over(fill), fill)
            let passes = effective >= minimum
            failures += passes ? 0 : 1
            let row = [
                token, appearance.name, fill.hex, RGB.black.hex, String(format: "%.2f", defaultRatio),
                override?.hex ?? "none", String(format: "%.2f", effective), passes ? "pass" : "FAIL",
            ]
            print("| " + row.joined(separator: " | ") + " |")
        }
    }
    return failures
}

print("")
print(failures == 0 ? "contrast: ok (minimum \(minimum):1)" : "contrast: FAIL (\(failures) row(s) below \(minimum):1)")
exit(failures == 0 ? 0 : 1)
