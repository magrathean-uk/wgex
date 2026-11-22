// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct MacFidelityTests {
    @Test(arguments: [
        (ProtectionVerdict.protected, "checkmark.shield", "Protection measured"),
        (.connecting, "hourglass", "Protection pending"),
        (.reasserting, "arrow.trianglehead.2.clockwise.rotate.90", "Reconnecting"),
        (.blocked, "lock", "Traffic blocked"),
        (.captiveWindow, "timer", "Unprotected"),
        (.unprotected, "shield.slash", "Unprotected"),
        (.unknown, "questionmark.circle", "Status reported"),
        (.stale, "icloud.slash", "Last known"),
        (.inactive, "shield", "Inactive"),
    ])
    func `v2 glyph and provenance table`(_ verdict: ProtectionVerdict, _ glyph: String, _ provenance: String) {
        #expect(verdict.glyph == glyph)
        #expect(verdict.provenanceTitle == provenance)
        if [.unknown, .stale, .inactive, .connecting, .reasserting].contains(verdict) {
            #expect(verdict.colour == .unknown)
        }
    }

    @Test func `captive countdown is clamped and available inside the orb`() {
        let now = PresentationCases.now
        let presentation = ProtectionPresentation(status: PresentationCases.status(
            .captiveWindow(PresentationCases.generation, expires: now.addingTimeInterval(272)),
            .captiveWindow(expires: now.addingTimeInterval(272)),
        ), context: .init(platform: .mac, now: now))
        #expect(presentation.countdownText(at: now) == "4:32")
        #expect(presentation.ring == .solid)
        #expect(presentation.countdownText(at: now.addingTimeInterval(273)) == "0:00")
        #expect(ProtectionPresentation.inactive(activeTunnel: "Home").countdownText(at: now) == nil)
    }

    @Test func `inactive selection never claims the active tunnel is unprotected`() {
        let presentation = ProtectionPresentation.inactive(activeTunnel: "Home")
        #expect(presentation.verdict == .inactive)
        #expect(presentation.primary == "Inactive")
        #expect(presentation.action == .connect)
        #expect(presentation.colour == .unknown)
        #expect(presentation.secondary.contains("Home"))
    }

    @Test func `actions use the agreed title case and vocabulary`() {
        #expect(UserStrings.connect == "Connect")
        #expect(UserStrings.disconnect == "Disconnect")
        #expect(UserStrings.reconnect == "Reconnect")
        #expect(ProtectionAction.connect.title == "Connect")
        #expect(ProtectionAction.disconnect.title == "Disconnect")
        #expect(ProtectionAction.endCaptiveWindow.title == "End Captive Window")
        #expect(ProtectionAction.checkAgain.title == "Check Again")
        #expect(ProtectionAction.reconnect.title == "Reconnect")
        #expect(MacStrings.profiles == "Tunnels")
        #expect(UserStrings.events == "Events")
        #expect(UserStrings.editProfile == "Edit Profile")
        #expect(UserStrings.connectionAtStartup == "Connection at startup")
    }

    @Test func `no report is stale unknown evidence and received reports retain their own provenance`() {
        let now = PresentationCases.now
        let first = ProtectionPresentation(status: .idle, context: .init(platform: .mac, now: now, staleness: .stale(since: .distantPast)))
        #expect(first.verdict == .unknown)
        #expect(first.primary == "Status unknown")
        #expect(first.isStale)
        #expect(first.provenanceTitle == "Status unknown")
        let stale = ProtectionPresentation(
            status: .idle,
            context: .init(platform: .mac, now: now, staleness: .stale(since: now.addingTimeInterval(-20))),
        )
        #expect(stale.primary == "Service not responding")
        #expect(stale.provenanceTitle == "Last known")
        let reportedUnknown = ProtectionPresentation(
            status: PresentationCases.status(.idle, .unknown),
            context: .init(platform: .mac, now: now),
        )
        #expect(!reportedUnknown.isStale)
        #expect(reportedUnknown.provenanceTitle == "Status reported")
    }

    @MainActor @Test func `direct transport labels are neutral and relay labels are secondary blue`() {
        let presentation = ProtectionPresentation.inactive(activeTunnel: "Home")
        let direct = ConnectionOrb(presentation: presentation, transportName: "Direct WireGuard") { _ in }
        let relay = ConnectionOrb(presentation: presentation, transportName: "Relay") { _ in }
        #expect(direct.chips.first?.colour == .unknown)
        #expect(relay.chips.first?.colour == .transport)
    }
}
