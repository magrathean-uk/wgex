// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct FormattingTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test func `the Mac copy catalogue is complete and uses the agreed vocabulary`() {
        #expect(MacStrings.catalogue.count + PlatformStrings.catalogue.count > 400)
        #expect(MacStrings.catalogue.allSatisfy { !$0.isEmpty && !$0.contains("On-Demand") })
        #expect(MacStrings.tunnels == UserStrings.tunnels)
        #expect(MacStrings.events == UserStrings.events)
        #expect(EditorStrings.title == "Tunnel editor")
        #expect(MacStrings.aMatchingProfileAlreadyExists == "A matching tunnel already exists")
        #expect(MacStrings.noReportYet == "No status received yet. Protection cannot be verified.")
    }

    @Test(arguments: [
        (0.0, "0 B/s"), (999, "999 B/s"), (1000, "1.0 kB/s"), (1500, "1.5 kB/s"), (9949, "9.9 kB/s"), (9960, "10 kB/s"),
        (12345, "12 kB/s"), (999_400, "999 kB/s"), (999_600, "1.0 MB/s"), (1_234_567, "1.2 MB/s"), (3.4e9, "3.4 GB/s"),
    ])
    func `rates use decimal units with one decimal below ten`(_ rate: Double, _ text: String) {
        #expect(UIFormat.rate(rate) == text)
    }

    @Test
    func `unusable rates are unavailable, never zero`() {
        #expect(UIFormat.rate(-1) == "Unavailable")
        #expect(UIFormat.rate(.nan) == "Unavailable")
        #expect(UIFormat.rate(.infinity) == "Unavailable")
        #expect(StatValue.unavailable.text == "Unavailable")
    }

    @Test
    func `byte counts`() {
        #expect(UIFormat.bytes(0) == "0 B")
        #expect(UIFormat.bytes(1536) == "1.5 kB")
        #expect(UIFormat.bytes(42_000_000_000) == "42 GB")
        #expect(UIFormat.bytes(.max) == "18446744 TB")
    }

    @Test(arguments: [
        (-5.0, "0 s"),
        (0, "0 s"),
        (18, "18 s"),
        (59.9, "59 s"),
        (60, "1 min"),
        (180, "3 min"),
        (7200, "2 h"),
        (345_600, "4 d")
    ])
    func `handshake ages`(_ seconds: TimeInterval, _ text: String) {
        #expect(UIFormat.age(now.addingTimeInterval(-seconds), now: now) == text)
    }

    @Test
    func `handshake age lines`() {
        #expect(UIFormat.ago(now.addingTimeInterval(-18), now: now) == "18 s ago")
        #expect(HealthDescription.handshakeClause(now.addingTimeInterval(-180), now: now) == "last handshake 3 min ago")
        #expect(HealthDescription.handshakeClause(nil, now: now) == "no handshake yet")
        let quiet = TunnelHealth(level: .healthy, lastHandshake: now.addingTimeInterval(-18), rxRate: 0, txRate: 0)
        #expect(HealthDescription.line(for: quiet, now: now) == "Connected, last handshake 18 s ago")
        #expect(StatValue.age(since: now.addingTimeInterval(-18), now: now).text == "18 s ago")
    }

    @Test(arguments: [
        (272.0, "4:32"), (5, "0:05"), (0.2, "0:01"), (0, "0:00"), (-3, "0:00"), (60, "1:00"), (300, "5:00"), (3723, "1:02:03"),
    ])
    func `countdowns round up and stop at zero`(_ remaining: TimeInterval, _ text: String) {
        #expect(UIFormat.countdown(remaining) == text)
    }

    @Test
    func `countdown copy and spoken form`() {
        #expect(CaptiveWindowCopy.message(remaining: 272) == "Unprotected for 4:32 to sign in to this network")
        #expect(CaptiveWindowCopy.message(remaining: 0) == "Sign-in window ended. Restoring protection")
        #expect(UIFormat.spokenDuration(272) == "4 minutes 32 seconds")
        #expect(UIFormat.spokenDuration(60) == "1 minute")
        #expect(UIFormat.spokenDuration(61) == "1 minute 1 second")
        #expect(UIFormat.spokenDuration(1) == "1 second")
        #expect(CaptiveWindowCopy.spokenMessage(remaining: 272) == "Unprotected for 4 minutes 32 seconds to sign in to this network")
    }

    @Test
    func `event descriptions never show error payloads`() throws {
        let legacy = Data(#"{"invalidConfiguration":{"_0":"PrivateKey = something"}}"#.utf8)
        let error = try JSONDecoder().decode(TunnelError.self, from: legacy)
        let text = EventDescription.describe(.failed(error)).text
        #expect(text == "Activation failed: the configuration is invalid")
        #expect(EventDescription.describe(.pathChanged).text == "Network changed, reconnecting")
    }

    @Test(arguments: [InvalidConfigurationReason.invalidProfile, .statisticsInterval])
    func `finite validation reasons preserve the existing copy`(_ reason: InvalidConfigurationReason) {
        #expect(EventDescription.describe(.failed(.invalidConfiguration(reason))).text == "Activation failed: the configuration is invalid")
    }

    @Test
    func `the timeline is newest first and bounded`() {
        let events = (0 ..< 40).map { TunnelEvent(date: now.addingTimeInterval(Double($0)), kind: .handshakeCompleted, generation: nil) }
        let timeline = EventDescription.timeline(events)
        #expect(timeline.count == 32)
        #expect(timeline.first?.date == now.addingTimeInterval(39))
        #expect(timeline.last?.date == now.addingTimeInterval(8))
    }
}
