// SPDX-License-Identifier: MIT

import Testing
import WGEXUI

private struct MacAnnouncementTests {
    @Test func `verdict changes announce atomically without repeating age or traffic updates`() throws {
        var announcements = AccessibilityAnnouncementState()
        let protected = try #require(PresentationCases.all.first { $0.expected == .protected }?.presentation)
        let unknown = try #require(PresentationCases.all.first { $0.expected == .unknown }?.presentation)
        #expect(announcements.messages(presentation: protected, toast: nil).isEmpty)
        #expect(announcements.messages(presentation: protected, toast: nil).isEmpty)
        #expect(announcements.messages(presentation: unknown, toast: nil) == [unknown.accessibilityLabel])
        #expect(announcements.messages(presentation: unknown, toast: nil).isEmpty)
    }

    @Test func `a toast announces once and the same message can announce after dismissal`() {
        var announcements = AccessibilityAnnouncementState()
        let presentation = ProtectionPresentation.inactive(activeTunnel: "Home")
        #expect(announcements.messages(presentation: presentation, toast: "Fixture message") == ["Fixture message"])
        #expect(announcements.messages(presentation: presentation, toast: "Fixture message").isEmpty)
        #expect(announcements.messages(presentation: presentation, toast: nil).isEmpty)
        #expect(announcements.messages(presentation: presentation, toast: "Fixture message") == ["Fixture message"])
    }
}
