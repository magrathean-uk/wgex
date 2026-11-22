// SPDX-License-Identifier: MIT

import Foundation
import SwiftUI
import Testing
import WGEXUI

private struct ContrastTests {
    @Test(arguments: StateColor.allCases, ContrastAppearance.allCases)
    func `plain tinted labels meet body text contrast`(_ token: StateColor, _ appearance: ContrastAppearance) {
        let resolved = token.labelColor(for: appearance.isDark ? .dark : .light).resolve(in: appearance.environment)
        let colour = ContrastColour(
            red: Double(resolved.red),
            green: Double(resolved.green),
            blue: Double(resolved.blue),
            opacity: Double(resolved.opacity),
        ).composited(over: appearance.background)
        #expect(ContrastColour.ratio(colour, appearance.background) >= 4.5, "\(token) \(appearance): \(colour.hex)")
    }

    @Test(arguments: StateColor.allCases, ContrastAppearance.allCases)
    func `text on every state colour meets 4.5 to 1`(_ token: StateColor, _ appearance: ContrastAppearance) {
        let result = token.contrast(in: appearance)
        #expect(result.passes, "\(token) \(appearance): \(result.text.hex) on \(result.fill.hex) is \(result.ratio)")
    }

    @Test
    func `the high-contrast override is the one the script asked for`() {
        let overridden = StateColor.unknown.contrast(in: .lightIncreased)
        #expect(overridden.text.hex == "#FFFFFF")
        #expect(StateColor.unknown.contrast(in: .light).text.hex == "#000000")
        #expect(StateColor.allCases.filter { $0.foregroundOverrideName != nil } == [.unknown])
    }

    @Test
    func `WCAG maths`() {
        #expect(abs(ContrastColour.ratio(.black, .white) - 21) < 0.0001)
        #expect(ContrastColour.ratio(.white, .white) == 1)
        let grey = ContrastColour(red: 0, green: 0, blue: 0, opacity: 0.5).composited(over: .white)
        #expect(abs(grey.red - 0.5) < 0.0001)
        #expect(ContrastColour(red: 1, green: 0, blue: 0, opacity: 0.5).hex == "#FF0000 @0.50")
    }

    @Test
    func `only green, orange and red are protection colours`() {
        #expect(StateColor.allCases.filter(\.isProtectionColour) == [.protected, .blocked, .unprotected])
        #expect(StateColor.allCases.allSatisfy { !$0.meaning.isEmpty })
    }
}
