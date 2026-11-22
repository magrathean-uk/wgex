// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI
#if canImport(AppKit)
    import AppKit
#elseif canImport(UIKit)
    import UIKit
#endif

private struct ProtectionPresentationTests {
    @Test(arguments: PresentationCases.all)
    func `every state maps to a complete, truthful presentation`(_ testCase: PresentationCase) {
        let presentation = testCase.presentation
        #expect(presentation.verdict == testCase.expected)
        #expect(!presentation.primary.isEmpty)
        #expect(!presentation.secondary.isEmpty)
        #expect(presentation.accessibilityLabel.contains(presentation.primary))
        #expect(presentation.accessibilityLabel.contains(presentation.secondary))
        #expect(presentation.glyph == presentation.verdict.glyph)
        #expect(presentation.colour == presentation.verdict.colour)
        #expect(Self.symbolExists(presentation.glyph), "missing SF Symbol \(presentation.glyph)")
        if let chip = presentation.healthChip {
            #expect(Self.symbolExists(chip.glyph), "missing SF Symbol \(chip.glyph)")
            #expect(!chip.colour.isProtectionColour)
        }
        if presentation.verdict == .stale || presentation.verdict == .unknown {
            #expect(!presentation.colour.isProtectionColour)
            #expect(presentation.colour == .unknown)
        }
        let reportingUnavailable = if case .notReporting? = testCase.context.unknownReason {
            true
        } else {
            false
        }
        #expect(presentation.isStale == (testCase.context.staleness.since != nil || reportingUnavailable))
        #expect(presentation.secondary.range(of: "always protected", options: .caseInsensitive) == nil)
    }

    @Test
    func `the cases cover every verdict`() {
        #expect(Set(PresentationCases.all.map(\.expected)) == Set(ProtectionVerdict.allCases.filter { $0 != .inactive }))
    }

    @Test
    func `colour is never the only signal`() {
        var signals: [String: ProtectionVerdict] = [:]
        for presentation in PresentationCases.all.map(\.presentation) {
            let key = "\(presentation.glyph)|\(presentation.ring)|\(presentation.primary)"
            if let other = signals[key] {
                #expect(other == presentation.verdict, "\(key) is shared by \(other) and \(presentation.verdict)")
            }
            signals[key] = presentation.verdict
        }
        let glyphAndText = Set(ProtectionVerdict.allCases.map { "\($0.glyph)|\($0.chipTitle)" })
        #expect(glyphAndText.count == ProtectionVerdict.allCases.count)
    }

    @Test
    func `only protected, blocked and unprotected states use protection colours`() {
        for verdict in ProtectionVerdict.allCases {
            let expected: Set<ProtectionVerdict> = [.protected, .blocked, .captiveWindow, .unprotected]
            #expect(verdict.colour.isProtectionColour == expected.contains(verdict), "\(verdict)")
        }
    }

    @Test
    func `rings follow the plan`() {
        let rings = Dictionary(PresentationCases.all.map { ($0.expected, $0.presentation.ring) }, uniquingKeysWith: { first, _ in first })
        #expect(rings[.connecting] == .indeterminate)
        #expect(rings[.protected] == .solid)
        #expect(rings[.reasserting] == .dashed)
        #expect(rings[.blocked] == .solid)
        #expect(rings[.unprotected] == RingStyle.none)
        #expect(rings[.unknown] == .solid)
        #expect(rings[.stale] == RingStyle.none)
    }

    @Test
    func `copy matches the copy deck`() throws {
        let byName = Dictionary(uniqueKeysWithValues: PresentationCases.all.map { ($0.name, $0.presentation) })
        let captive = try #require(byName["captive window"])
        #expect(captive.secondary == "Unprotected for 4:32 to sign in to this network")
        #expect(captive.countdownExpiry == PresentationCases.now.addingTimeInterval(272))
        #expect(byName["captive window, expired"]?.secondary == "Sign-in window ended. Restoring protection")
        #expect(byName["protected, unresponsive"]?.secondary == "Connected, peer not responding (last handshake 3 min ago)")
        #expect(byName["protected, unresponsive, never"]?.secondary == "Connected, peer not responding (no handshake yet)")
        #expect(byName["protected, idle"]?.secondary == "Connected, idle")
        #expect(byName["protected, transferring"]?.secondary == "Connected, transferring")
        #expect(byName["unknown, not reporting"]?.secondary == "Background service has not reported for 12 s")
        #expect(byName["unknown, iOS not reporting"]?.secondary == "VPN extension has not reported for 12 s")
        #expect(byName["reasserting, pathChanged"]?
            .secondary == "Network changed. Checking protection again. Traffic outside the tunnel is blocked meanwhile")
        #expect(byName["unprotected, idle"]?.secondary == "Traffic can leave outside the tunnel")
        #expect(byName["unsupported, connected"]?.secondary.hasPrefix("Apple TV cannot enforce a kill switch") == true)
        #expect(byName["stale"]?.secondary == "Last report 42 s ago. Values shown are stale and may be wrong.")
        #expect(byName["protected, unresponsive"]?.healthChip?.title == "No response")
    }

    @Test
    func `actions follow the state`() {
        let actions = Dictionary(
            PresentationCases.all.map { ($0.expected, $0.presentation.action) },
            uniquingKeysWith: { first, _ in first },
        )
        #expect(actions[.protected] == .disconnect)
        #expect(actions[.connecting] == .cancel)
        #expect(actions[.blocked] == .reconnect)
        #expect(actions[.captiveWindow] == .endCaptiveWindow)
        #expect(actions[.unprotected] == .connect)
        #expect(actions[.unknown] == .checkAgain)
        #expect(ProtectionAction.allCases.allSatisfy { !$0.title.isEmpty })
    }

    @Test
    func `staleness is evaluated against the threshold`() {
        let now = PresentationCases.now
        #expect(Staleness.evaluate(lastUpdate: now.addingTimeInterval(-5), now: now) == .fresh)
        #expect(Staleness.evaluate(lastUpdate: now.addingTimeInterval(-16), now: now) == .stale(since: now.addingTimeInterval(-16)))
        #expect(Staleness.evaluate(lastUpdate: nil, now: now) == .stale(since: .distantPast))
    }

    private static func symbolExists(_ name: String) -> Bool {
        #if canImport(AppKit)
            NSImage(systemSymbolName: name, accessibilityDescription: nil) != nil
        #elseif canImport(UIKit)
            UIImage(systemName: name) != nil
        #else
            true
        #endif
    }
}
