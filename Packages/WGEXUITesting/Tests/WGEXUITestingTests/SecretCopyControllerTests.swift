// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXTesting
import WGEXUI
import WGEXUITesting

private struct SecretCopyControllerTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let placeholder = "test-placeholder-value"

    private func controller(_ policy: SecretCopyPolicy, _ pasteboard: FakeSecretPasteboard, _ clock: FakeClock) -> SecretCopyController {
        let now = now
        return SecretCopyController(policy: policy, pasteboard: pasteboard, clock: clock, now: { now })
    }

    @Test
    func `macOS clears the pasteboard after 60 seconds`() async {
        let pasteboard = FakeSecretPasteboard()
        let clock = FakeClock()
        let copier = controller(.mac, pasteboard, clock)
        #expect(copier.copy(placeholder) == .copied(expiresAt: now.addingTimeInterval(60)))
        #expect(pasteboard.contents == placeholder)
        #expect(pasteboard.lastOptions == SecretPasteboardOptions(localOnly: true, expiresAt: nil))
        await clock.waitForSleepers(1)
        clock.advance(by: .seconds(59))
        #expect(pasteboard.contents == placeholder)
        clock.advance(by: .seconds(1))
        await copier.scheduledClear?.value
        #expect(pasteboard.contents == nil)
        #expect(pasteboard.clearCount == 1)
    }

    @Test
    func `macOS leaves a newer copy alone`() async {
        let pasteboard = FakeSecretPasteboard()
        let clock = FakeClock()
        let copier = controller(.mac, pasteboard, clock)
        copier.copy(placeholder)
        await clock.waitForSleepers(1)
        pasteboard.simulateOtherCopy("something else")
        clock.advance(by: .seconds(60))
        await copier.scheduledClear?.value
        #expect(pasteboard.contents == "something else")
        #expect(pasteboard.clearCount == 0)
    }

    @Test
    func `a second copy restarts the 60 seconds`() async {
        let pasteboard = FakeSecretPasteboard()
        let clock = FakeClock()
        let copier = controller(.mac, pasteboard, clock)
        copier.copy(placeholder)
        await clock.waitForSleepers(1)
        clock.advance(by: .seconds(30))
        copier.copy(placeholder)
        await clock.waitForSleepers(1)
        clock.advance(by: .seconds(30))
        #expect(pasteboard.contents == placeholder)
        clock.advance(by: .seconds(30))
        await copier.scheduledClear?.value
        #expect(pasteboard.contents == nil)
        #expect(pasteboard.clearCount == 1)
    }

    @Test
    func `iOS writes local-only with a 60 second system expiry`() {
        let pasteboard = FakeSecretPasteboard()
        let clock = FakeClock()
        let copier = controller(.iOS, pasteboard, clock)
        #expect(copier.copy(placeholder) == .copied(expiresAt: now.addingTimeInterval(60)))
        #expect(pasteboard.lastOptions == SecretPasteboardOptions(localOnly: true, expiresAt: now.addingTimeInterval(60)))
        #expect(copier.scheduledClear == nil)
        #expect(clock.sleeperCount == 0)
    }

    @Test
    func `tvOS and missing secrets copy nothing`() {
        let pasteboard = FakeSecretPasteboard()
        let clock = FakeClock()
        let television = controller(.tvOS, pasteboard, clock)
        #expect(!television.isAvailable)
        #expect(television.copy(placeholder) == .unavailable)
        let phone = controller(.iOS, pasteboard, clock)
        #expect(phone.copy(nil) == .nothingToCopy)
        #expect(phone.copy("") == .nothingToCopy)
        #expect(pasteboard.changeCount == 0)
        for outcome in [SecretCopyOutcome.copied(expiresAt: now), .unavailable, .nothingToCopy] {
            #expect(!outcome.message.isEmpty)
        }
    }
}
