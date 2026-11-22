// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacStatusTruthTests {
        @Test
        func `relaunch uses daemon active profile and receipt never refreshes cached evidence`() {
            let first = TunnelProfile(name: "First")
            let active = TunnelProfile(name: "Active")
            let now = Date(timeIntervalSince1970: 1000)
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: false),
                profiles: [first, active],
                now: now,
            )
            model.daemonHooks.continuousNow = { XPCClock.continuousSeconds }
            var status = TunnelStatus.idle
            status.phase = .active(Generation(rawValue: 1))
            status.protection = .protected
            status.activeProfileID = active.id
            status.sequence = 4
            status.measuredAt = now.addingTimeInterval(-20)
            status.measuredAtContinuous = XPCClock.continuousSeconds - 20
            model.receiveConnection(.connected(daemonBuild: 10))
            model.receive(status, at: now)
            #expect(model.activeProfileID == active.id)
            #expect(model.lastStatusAt == status.measuredAt)
            #expect(model.presentation.verdict != .protected)
            model.receive(status, at: now.addingTimeInterval(1))
            #expect(model.presentation.verdict != .protected)
        }

        @Test
        func `recovering status admits profile repair without weakening ordinary deletion policy`() throws {
            var status = TunnelStatus.idle
            status.phase = .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false)
            status.protection = .blocked
            #expect(!MacProfileDeletionPolicy.canDelete(status))
            status.recoveryFailureReason = .profileUnavailable
            #expect(MacProfileDeletionPolicy.canDelete(status))
            try MacProfileDeletionPolicy.check(status)
        }

        @Test
        func `not reporting uses copy deck words and no protection colour`() {
            let since = Date(timeIntervalSince1970: 1000)
            var status = TunnelStatus.idle
            status.protection = .unknown
            let presentation = ProtectionPresentation(status: status, context: .init(
                platform: .mac, now: since.addingTimeInterval(20), unknownReason: .notReporting(since: since),
            ))
            #expect(presentation.secondary == "Background service has not reported for 20 s")
            #expect(presentation.colour == .unknown)
            #expect(presentation.action == .checkAgain)
            #expect(presentation.isStale)
            #expect(presentation.provenanceTitle == MacStrings.statusUnknown)
        }
    }
#endif
