// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacReportHistoryTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let profile = TunnelProfile(name: "Fixture")
        private var protectedStatus: TunnelStatus {
            .init(
                phase: .active(.init(rawValue: 1)),
                protection: .protected,
                transport: nil,
                health: .init(level: .healthy, lastHandshake: date, rxRate: 1500, txRate: 500),
                recentEvents: [],
            )
        }

        @Test(arguments: [false, true])
        func `a lost service retains last-known evidence without claiming cached protection`(_ streamEnds: Bool) async {
            let model = model(reports: [protectedStatus])
            model.receiveConnection(.connected(daemonBuild: 42))
            model.receive(protectedStatus, at: date)
            for index in 0 ... 1 {
                model.receiveStatistics(.init(
                    generation: 1, sampledAt: date.addingTimeInterval(Double(index * 2)), interfaceName: "fixture", listenPort: nil,
                    peers: [.init(
                        publicKey: profile.interface.publicKey,
                        endpoint: nil,
                        lastHandshake: date,
                        rxBytes: UInt64(index * 3000),
                        txBytes: UInt64(index * 1000),
                        persistentKeepalive: nil,
                    )],
                ))
            }
            #expect(model.killSwitchDescription == "Armed")
            #expect(!model.detailPresentation.isStale)
            #expect(model.traffic.hasMeasurements)
            if streamEnds {
                await model.observeTunnel()
            } else {
                model.receiveConnection(.disconnected(lastError: nil))
            }
            #expect(model.lastStatusAt == nil)
            #expect(model.status.protection == .protected)
            #expect(model.presentation.verdict == .stale)
            #expect(model.presentation.primary == "Service not responding")
            #expect(model.presentation.provenanceTitle == "Last known")
            #expect(model.killSwitchDescription != "Armed")
            #expect(model.detailPresentation.isStale)
            #expect(model.presentation.isStale)
            #expect(model.traffic.hasMeasurements)
            for (title, value) in [(MacStrings.download, model.downloadValue), (MacStrings.upload, model.uploadValue)] {
                #expect(StatTile.accessibilityLabel(title: title, value: value, isStale: model.detailPresentation.isStale)
                    .hasSuffix(", stale"))
            }
            model.receiveConnection(.connected(daemonBuild: 43))
            #expect(model.presentation.isStale)
            model.receive(protectedStatus, at: date.addingTimeInterval(20))
            #expect(!model.presentation.isStale)
            #expect(model.presentation.verdict == .protected)
        }

        @Test(arguments: [false, true])
        func `never-reported status stays unknown and cannot expose current protection`(_ streamEnds: Bool) async {
            let model = model(reports: [])
            if streamEnds {
                await model.observeTunnel()
            } else {
                model.receiveConnection(.disconnected(lastError: nil))
            }
            #expect(model.lastStatusAt == nil)
            #expect(model.presentation.verdict == .unknown)
            #expect(model.presentation.primary == "Status unknown")
            #expect(model.presentation.secondary == MacStrings.noReportYet)
            #expect(model.presentation.provenanceTitle == "Status unknown")
            #expect(model.lastReceivedReportAt == nil)
            #expect(model.presentation.isStale)
            #expect(model.killSwitchDescription != "Armed")
            #expect(model.downloadValue == .unavailable)
            #expect(model.uploadValue == .unavailable)
            #expect(!model.traffic.hasMeasurements)
        }

        @Test func `a supplied initial report also survives lost reachability as last-known evidence`() {
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [profile],
                status: protectedStatus,
                now: date,
            )
            model.receiveConnection(.disconnected(lastError: nil))
            #expect(model.lastReceivedReportAt == date)
            #expect(model.presentation.provenanceTitle == "Last known")
            #expect(model.presentation.isStale)
            #expect(model.killSwitchDescription != "Armed")
        }

        private func model(reports: [TunnelStatus]) -> MacShellModel {
            MacShellModel(
                dependencies: .init(backend: FiniteReportBackend(reports: reports), service: FakeServiceController(), simulated: true),
                profiles: [profile],
                now: date,
            )
        }
    }

    private nonisolated struct FiniteReportBackend: TunnelBackend {
        let reports: [TunnelStatus]
        private let fake = FakeTunnelBackend()
        var capabilities: BackendCapabilities {
            fake.capabilities
        }

        func install(_ profile: TunnelProfile) async throws(TunnelError) {
            try await fake.install(profile)
        }

        func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
            try await fake.remove(id, purgeSecrets: purgeSecrets)
        }

        func start(_ id: UUID, transport: TransportID?) async throws(TunnelError) {
            try await fake.start(id, transport: transport)
        }

        func stop(_ id: UUID) async throws(TunnelError) {
            try await fake.stop(id)
        }

        func statistics() async throws(TunnelError) -> TunnelStatistics {
            try await fake.statistics()
        }

        func statusUpdates() -> AsyncStream<TunnelStatus> {
            AsyncStream { continuation in
                for report in reports {
                    continuation.yield(report)
                }
                continuation.finish()
            }
        }
    }
#endif
