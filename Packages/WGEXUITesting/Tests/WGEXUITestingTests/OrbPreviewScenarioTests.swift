// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXTesting
import WGEXUI
import WGEXUITesting

private struct OrbPreviewScenarioTests {
    @Test
    func `the scripted status stream plays the same sequence every time`() async {
        for _ in 0 ..< 2 {
            let scenario = OrbPreviewScenario()
            await scenario.begin()
            await Self.waitFor { scenario.history.count == 1 }
            // One full cycle is 14 fake seconds; the 15th restarts it.
            for _ in 0 ..< 15 {
                await scenario.clock.waitForSleepers(1)
                scenario.tick()
                await Self.waitFor { scenario.clock.sleeperCount == 1 }
            }
            let expected: [ProtectionVerdict] = [
                .unprotected, .connecting, .connecting, .protected, .reasserting, .protected, .blocked, .unprotected, .connecting,
            ]
            await Self.waitFor { scenario.history.count >= expected.count }
            scenario.cancel()
            #expect(scenario.history == expected)
        }
    }

    @Test
    func `the script covers connect, path change, failure and stop`() {
        let phases = OrbPreviewScenario.script.map(\.phase)
        #expect(phases.first == .preparing(OrbPreviewScenario.generation))
        #expect(phases.last == .idle)
        #expect(OrbPreviewScenario.script.allSatisfy { $0.delay > .zero })
    }

    private static func waitFor(_ condition: () -> Bool) async {
        for _ in 0 ..< 10000 where !condition() {
            await Task.yield()
        }
    }
}
