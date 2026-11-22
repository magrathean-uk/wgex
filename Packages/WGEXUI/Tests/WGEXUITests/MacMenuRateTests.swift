// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacMenuRateTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let key = TunnelProfile(name: "Fixture").interface.publicKey

        private func sample(_ seconds: Double, generation: UInt64 = 1, received: UInt64, sent: UInt64 = 0) -> TunnelStatistics {
            TunnelStatistics(
                generation: generation,
                sampledAt: date.addingTimeInterval(seconds),
                interfaceName: "utun7",
                listenPort: nil,
                peers: [.init(
                    publicKey: key,
                    endpoint: nil,
                    lastHandshake: date,
                    rxBytes: received,
                    txBytes: sent,
                    persistentKeepalive: nil,
                )],
            )
        }

        @Test func `rate divides actual byte differences by elapsed seconds`() throws {
            var traffic = MacSessionTraffic()
            traffic.append(sample(0, received: 100, sent: 50))
            #expect(traffic.rates(at: date, generation: 1) == nil)
            traffic.append(sample(2.5, received: 1100, sent: 300))
            let rate = try #require(traffic.rates(at: date.addingTimeInterval(2.5), generation: 1))
            #expect(rate.download == 400)
            #expect(rate.upload == 100)
            #expect(traffic.rates(at: date.addingTimeInterval(2), generation: 1) == nil)
            #expect(traffic.rates(at: date.addingTimeInterval(7.51), generation: 1) == nil)
            #expect(traffic.rates(at: date.addingTimeInterval(2.5), generation: 2) == nil)
            traffic.append(sample(4.5, received: 1100, sent: 300))
            #expect(traffic.rates(at: date.addingTimeInterval(4.5), generation: 1)?.download == 0)
        }

        @Test func `large counters retain single byte rate precision`() {
            var traffic = MacSessionTraffic()
            traffic.append(sample(0, received: UInt64.max - 10))
            traffic.append(sample(2, received: UInt64.max - 8))
            #expect(traffic.rates(at: date.addingTimeInterval(2), generation: 1)?.download == 1)
        }

        @Test func `old samples do not replace live rates and resets need a fresh baseline`() {
            var traffic = MacSessionTraffic()
            traffic.append(sample(0, received: 1000))
            traffic.append(sample(2, received: 2000))
            traffic.append(sample(1, received: 9000))
            traffic.append(sample(2, received: 9000))
            #expect(traffic.rates(at: date.addingTimeInterval(2), generation: 1)?.download == 500)
            traffic.append(sample(4, received: 10))
            #expect(traffic.rates(at: date.addingTimeInterval(4), generation: 1) == nil)
            traffic.append(sample(6, received: 110))
            #expect(traffic.rates(at: date.addingTimeInterval(6), generation: 1)?.download == 50)
            traffic.append(sample(8, generation: 2, received: 900))
            #expect(traffic.rates(at: date.addingTimeInterval(8), generation: 2) == nil)
            traffic.append(sample(10, generation: 2, received: 1000))
            #expect(traffic.rates(at: date.addingTimeInterval(10), generation: 2)?.download == 50)
            traffic.append(sample(20, generation: 2, received: 100_000))
            #expect(traffic.rates(at: date.addingTimeInterval(20), generation: 2) == nil)
            traffic.append(sample(22, generation: 2, received: 100_200))
            #expect(traffic.rates(at: date.addingTimeInterval(22), generation: 2)?.download == 100)
        }

        @Test func `multiple peers sum but missing peers and individual resets invalidate the rate`() throws {
            let secondKey = try PublicKey(rawValue: Data(repeating: 1, count: 32))
            var first = sample(0, received: 1000)
            first.peers.append(.init(
                publicKey: secondKey,
                endpoint: nil,
                lastHandshake: date,
                rxBytes: 1000,
                txBytes: 0,
                persistentKeepalive: nil,
            ))
            var next = first
            next.sampledAt = date.addingTimeInterval(2)
            next.peers[0].rxBytes = 1400
            next.peers[1].rxBytes = 1600
            var traffic = MacSessionTraffic()
            traffic.append(first)
            traffic.append(next)
            #expect(traffic.rates(at: next.sampledAt, generation: 1)?.download == 500)
            next.sampledAt = date.addingTimeInterval(4)
            next.peers[0].rxBytes = 100
            next.peers[1].rxBytes = 5000
            traffic.append(next)
            #expect(traffic.rates(at: next.sampledAt, generation: 1) == nil)
            next.sampledAt = date.addingTimeInterval(6)
            next.peers.removeLast()
            traffic.append(next)
            #expect(traffic.rates(at: next.sampledAt, generation: 1) == nil)
            next.sampledAt = date.addingTimeInterval(8)
            next.peers = []
            traffic.append(next)
            #expect(traffic.rates(at: next.sampledAt, generation: 1) == nil)
        }

        @Test func `statistics request failure hides live values and a retry restores measured rates`() async {
            let faults = FaultInjector()
            let backend = FakeTunnelBackend(faults: faults)
            let profile = TunnelProfile(name: "Fixture")
            var status = TunnelStatus(
                phase: .active(.init(rawValue: 1)),
                protection: .protected,
                transport: nil,
                health: .idle,
                recentEvents: [],
            )
            status.measuredAt = date
            status.activeProfileID = profile.id
            let model = MacShellModel(
                dependencies: .init(backend: backend, service: FakeServiceController(), simulated: true),
                profiles: [profile],
                status: status,
                now: date,
            )
            model.receiveStatistics(sample(-2, received: 100))
            model.receiveStatistics(sample(0, received: 300))
            faults.arm("statistics", error: TunnelError.backendUnavailable)
            await model.sampleStatistics()
            #expect(model.statistics == nil)
            #expect(MacMenuPresentation(model: model).rows.contains { $0.title == "Download: Unavailable (Unavailable)" })
            backend.setStatistics(sample(0, received: 300))
            await model.sampleStatistics()
            #expect(model.statistics == nil)
            backend.setStatistics(sample(2, received: 500))
            model.tick(at: date.addingTimeInterval(2))
            await model.sampleStatistics()
            #expect(model.statistics?.sampledAt == date.addingTimeInterval(2))
            model.receiveStatistics(sample(1, received: 9999))
            #expect(model.statistics?.sampledAt == date.addingTimeInterval(2))
            #expect(MacMenuPresentation(model: model).rows.contains { $0.title == "Download: 100 B/s (500 B)" })
        }
    }
#endif
