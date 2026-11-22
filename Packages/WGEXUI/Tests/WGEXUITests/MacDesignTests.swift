// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacDesignTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private func sample(_ seconds: Double, generation: UInt64 = 1, received: UInt64, sent: UInt64 = 0) -> TunnelStatistics {
            let profile = TunnelProfile(name: "Fixture")
            return TunnelStatistics(
                generation: generation,
                sampledAt: date.addingTimeInterval(seconds),
                interfaceName: "utun7",
                listenPort: 51820,
                peers: [PeerStatistics(
                    publicKey: profile.interface.publicKey,
                    endpoint: nil,
                    lastHandshake: date,
                    rxBytes: received,
                    txBytes: sent,
                    persistentKeepalive: nil,
                )],
            )
        }

        @Test func `traffic uses measured deltas and needs two samples`() throws {
            var traffic = MacSessionTraffic()
            traffic.append(sample(-2, received: 100, sent: 50))
            #expect(!traffic.hasMeasurements)
            traffic.append(sample(0, received: 300, sent: 80))
            #expect(traffic.hasMeasurements)
            let rate = try #require(traffic.rates(at: date, generation: 1))
            #expect(rate.download == 100)
            #expect(rate.upload == 15)
        }

        @Test func `counter reset generation change and out of order samples do not invent traffic`() {
            var traffic = MacSessionTraffic()
            traffic.append(sample(-4, received: 1000))
            traffic.append(sample(-2, received: 2000))
            traffic.append(sample(-3, received: 9000))
            #expect(traffic.rates(at: date.addingTimeInterval(-2), generation: 1)?.download == 500)
            traffic.append(sample(0, received: 10))
            #expect(!traffic.hasMeasurements)
            traffic.append(sample(5, generation: 2, received: 500))
            #expect(!traffic.hasMeasurements)
        }

        @Test func `a paused hour is unmeasured and the next delta uses a fresh baseline`() {
            var traffic = MacSessionTraffic()
            traffic.append(sample(0, received: 100))
            traffic.append(sample(3600, received: 1_000_000_100))
            #expect(!traffic.hasMeasurements)
            #expect(traffic.rates(at: date.addingTimeInterval(3600), generation: 1) == nil)
            traffic.append(sample(3602, received: 1_000_000_300))
            #expect(traffic.rates(at: date.addingTimeInterval(3602), generation: 1)?.download == 100)
            #expect(traffic.startedAt == nil)
        }

        @Test(arguments: [5.0, 5.01])
        func `sampling gap threshold is two and a half intervals`(_ gap: Double) {
            var traffic = MacSessionTraffic()
            traffic.append(sample(0, received: 100))
            traffic.append(sample(gap, received: 300))
            #expect(traffic.hasMeasurements == (gap <= 5))
        }

        @Test func `disconnect clears session and unrelated generation is ignored`() {
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                status: .init(
                    phase: .active(.init(rawValue: 1)),
                    protection: .protected,
                    transport: nil,
                    health: .idle,
                    recentEvents: [],
                ),
                now: date,
            )
            model.receiveStatistics(sample(-2, received: 100))
            model.receiveStatistics(sample(0, received: 200))
            #expect(model.traffic.hasMeasurements)
            model.receiveStatistics(sample(1, generation: 2, received: 9999))
            #expect(model.statistics?.generation == 1)
            model.receive(.idle, at: date)
            #expect(!model.traffic.hasMeasurements)
            #expect(model.statistics == nil)
        }

        @Test func `browsing inactive profiles does not attribute active measurements and switching stops first`() async throws {
            let backend = FakeTunnelBackend()
            let first = TunnelProfile(name: "Home")
            let second = TunnelProfile(name: "Cabin")
            try await backend.install(first)
            try await backend.start(first.id, transport: nil)
            var measured = backend.currentStatus
            measured.activeProfileID = first.id
            let model = MacShellModel(
                dependencies: .init(backend: backend, service: FakeServiceController(), simulated: true),
                profiles: [first, second],
                status: measured,
                now: date,
            )
            model.selectedProfileID = second.id
            #expect(model.canSelectProfile)
            #expect(model.selectedIsInactive)
            #expect(model.detailPresentation.primary == "Inactive")
            #expect(model.detailPresentation.verdict == .inactive)
            #expect(model.designPresentation.verdict == .protected)
            #expect(model.displayedStatistics == nil)
            await model.toggleConnection()
            measured = backend.currentStatus
            measured.activeProfileID = second.id
            model.receive(measured, at: date)
            #expect(model.activeProfileID == second.id)
            let stop = try #require(backend.calls.firstIndex(of: .stop(first.id)))
            let start = try #require(backend.calls.firstIndex(of: .start(second.id, transport: nil)))
            #expect(stop < start)
            // A stream can deliver the old stop snapshot after start returns.
            model.receive(.idle, at: date)
            model.receive(backend.currentStatus, at: date)
            #expect(model.activeProfileID == second.id)
        }

        @Test func `setup has three ordered steps numbered from zero`() {
            #expect(MacOnboardingStep.ordered == [.welcome, .backgroundService, .addTunnel])
            #expect(MacOnboardingStep.ordered.map(\.rawValue) == [0, 1, 2])
        }
    }
#endif
