// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacVerifierStateTests {
        @Test
        func `launch has no report rather than a zero second heartbeat gap`() {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: false))
            #expect(model.presentation.verdict == .unknown)
            #expect(model.presentation.secondary == MacStrings.noReportYet)
            #expect(!model.presentation.secondary.contains("0 s"))
        }

        @Test
        func `a responding service with old verification has distinct neutral evidence`() {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: false))
            var status = TunnelStatus.unreported
            status.phase = .active(.init(rawValue: 7))
            status.lastReportedAt = Date()
            status.serviceResponding = true
            status.verificationExpired = true
            model.receive(status, at: Date())
            model.receiveConnection(.connected(daemonBuild: 10))
            #expect(model.presentation.verdict == .unknown)
            #expect(model.presentation.colour == .unknown)
            #expect(model.presentation.reporterDetail == MacStrings.serviceResponding)
            #expect(model.presentation.secondary != MacStrings.noReportYet)
            #expect(!model.presentation.secondary.contains("has not reported"))
        }

        @Test
        func `simulated check again reads the fake without starting it again`() async throws {
            let backend = FakeTunnelBackend()
            let profile = TunnelProfile(name: "Fixture")
            let date = Date(timeIntervalSince1970: 1000)
            let model = MacShellModel(
                dependencies: .init(backend: backend, service: FakeServiceController(), simulated: true),
                profiles: [profile],
                status: .idle,
                now: date,
            )
            try await backend.install(profile)
            try await backend.start(profile.id, transport: nil)
            model.tick(at: date.addingTimeInterval(20))
            #expect(model.presentation.action == .checkAgain)
            await model.toggleConnection()
            #expect(model.status.phase == backend.currentStatus.phase)
            #expect(model.status.protection == backend.currentStatus.protection)
            #expect(backend.calls.filter { $0 == .start(profile.id, transport: nil) }.count == 1)
        }
    }
#endif
