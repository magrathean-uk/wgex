// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXUI

    @MainActor
    private struct MacSamplingTests {
        @Test(.timeLimit(.minutes(1))) func `sampling requires both visibility and an active tunnel`() async {
            let clock = SamplingClock()
            var requests = 0
            let sampler = MacStatisticsSampler(sleep: { await clock.wait() }, sample: { requests += 1 })
            sampler.update(visible: false, active: true)
            await clock.advance()
            #expect(requests == 0)
            sampler.update(visible: true, active: false)
            await clock.advance()
            #expect(requests == 0)
            sampler.update(visible: true, active: true)
            await clock.nextWait()
            #expect(requests == 1)
            await clock.advance()
            await clock.nextWait()
            #expect(requests == 2)
            sampler.update(visible: false, active: true)
            await clock.advance()
            #expect(requests == 2)
            sampler.update(visible: true, active: false)
            await clock.advance()
            #expect(requests == 2)
        }
    }

    @MainActor
    private final class SamplingClock {
        private var sleeper: CheckedContinuation<Void, Never>?
        private var observer: CheckedContinuation<Void, Never>?

        func wait() async {
            await withCheckedContinuation { continuation in
                sleeper = continuation
                observer?.resume(); observer = nil
            }
        }

        func nextWait() async {
            if sleeper != nil {
                return
            }
            await withCheckedContinuation { observer = $0 }
        }

        func advance() async {
            sleeper?.resume(); sleeper = nil
            await Task.yield()
        }
    }
#endif
