// SPDX-License-Identifier: MIT

import Testing
import WGEXTesting

private struct FakeClockTests {
    @Test
    func `sleepers resume only when time passes their deadline`() async throws {
        let clock = FakeClock()
        let sleeper = Task { try await clock.sleep(for: .seconds(10)) }
        await clock.waitForSleepers(1)
        clock.advance(by: .seconds(9))
        #expect(clock.sleeperCount == 1)
        clock.advance(by: .seconds(1))
        try await sleeper.value
        #expect(clock.sleeperCount == 0)
        #expect(clock.now.offset == .seconds(10))
    }

    @Test
    func `past deadlines return immediately`() async throws {
        let clock = FakeClock()
        clock.advance(by: .seconds(5))
        try await clock.sleep(until: clock.now.advanced(by: .seconds(-1)))
    }

    @Test
    func `cancellation wakes a sleeper with an error`() async {
        let clock = FakeClock()
        let sleeper = Task { try await clock.sleep(for: .seconds(60)) }
        await clock.waitForSleepers(1)
        sleeper.cancel()
        await #expect(throws: CancellationError.self) { try await sleeper.value }
        #expect(clock.sleeperCount == 0)
    }
}
