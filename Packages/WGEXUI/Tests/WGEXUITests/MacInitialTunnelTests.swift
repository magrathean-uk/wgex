// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    /// SPEC 5.1 initial destination against the real backend's start-up: StatusBroadcast replays the client's unreported
    /// seed before the daemon reports, so only a daemon report (fresh, or its stale snapshot) settles the destination.
    @MainActor
    private struct MacInitialTunnelTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let home = TunnelProfile(name: "Home")
        private let cabin = TunnelProfile(name: "Cabin")
        private let lab = TunnelProfile(name: "Lab")

        private func daemonShell(_ profiles: [TunnelProfile]) -> MacShellModel {
            let shell = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: false),
                profiles: [], now: date,
            )
            shell.profiles = profiles
            shell.applyInitialTunnel()
            return shell
        }

        /// A measured report as DaemonClient.acceptStatus publishes it.
        private func report(_ id: UUID?) -> TunnelStatus {
            var status = TunnelStatus.idle
            if let id {
                status.phase = .active(Generation(rawValue: 1))
                status.protection = .protected
                status.activeProfileID = id
            }
            status.sequence = 1
            status.measuredAt = date
            status.measuredAtContinuous = 1
            status.serviceResponding = true
            return status
        }

        /// The client's snapshot when the daemon is unreachable and has never reported.
        private var unreachable: TunnelStatus {
            var status = TunnelStatus.unreported
            status.reportingUnavailable = true
            status.notReportingSince = date
            return status
        }

        @Test func `the launch seed never settles the destination and the first daemon report does`() {
            let shell = daemonShell([home, cabin, lab])
            #expect(shell.windowSelection == .tunnel(home.id))
            shell.receive(.unreported, at: date)
            #expect(shell.selectedProfileID == home.id)
            shell.receive(report(cabin.id), at: date)
            #expect(shell.windowSelection == .tunnel(cabin.id))
            // Settled once: later reports never move a window the user is reading.
            shell.receive(report(lab.id), at: date)
            #expect(shell.selectedProfileID == cabin.id)
        }

        @Test func `an inactive first report settles on the first tunnel and a later activation does not move it`() {
            let shell = daemonShell([home, cabin, lab])
            shell.receive(.unreported, at: date)
            shell.receive(report(nil), at: date)
            #expect(shell.selectedProfileID == home.id)
            shell.receive(report(cabin.id), at: date)
            #expect(shell.selectedProfileID == home.id)
            shell.routeWindow(.manageTunnels)
            #expect(shell.selectedProfileID == cabin.id)
        }

        @Test func `a report before the profiles load opens the active tunnel once they load`() {
            // The launch load failed, so the first report finds no profiles; MacAppModel.applicationActivated reloads them.
            let shell = daemonShell([])
            shell.receive(.unreported, at: date)
            shell.receive(report(cabin.id), at: date)
            #expect(shell.windowSelection == nil)
            shell.profiles = [home, cabin, lab]
            shell.reselectAfterReload()
            #expect(shell.selectedProfileID == cabin.id)
            shell.routeWindow(.manageTunnels)
            #expect(shell.selectedProfileID == cabin.id)
        }

        @Test func `a reload that drops a picked tunnel opens the first tunnel`() {
            let shell = daemonShell([home, cabin, lab])
            shell.receive(report(lab.id), at: date)
            shell.windowSelection = .tunnel(home.id)
            shell.profiles = [cabin, lab]
            shell.reselectAfterReload()
            #expect(shell.selectedProfileID == cabin.id)
        }

        @Test func `an action that selects the rule's own tunnel before the first daemon report is kept`() {
            let shell = daemonShell([home, cabin])
            shell.receive(.unreported, at: date)
            shell.receive(unreachable, at: date)
            // An import replacing Home, or a saved edit of it, re-selects the tunnel the rule chose.
            shell.selectByAction(home.id)
            shell.receive(report(cabin.id), at: date)
            #expect(shell.selectedProfileID == home.id)
            shell.routeWindow(.manageTunnels)
            #expect(shell.selectedProfileID == home.id)
        }

        @Test(arguments: [false, true])
        func `a daemon report replayed as the first update opens the active tunnel`(stale: Bool) {
            let shell = daemonShell([home, cabin, lab])
            var first = report(lab.id)
            if stale {
                // DaemonClient.evaluateStaleness keeps the daemon's report as the last report.
                first.lastReportedAt = first.measuredAt
                first.measuredAt = nil
                first.measuredAtContinuous = nil
                first.protection = .unknown
            }
            shell.receive(first, at: date)
            #expect(shell.selectedProfileID == lab.id)
        }

        @Test func `with no daemon report the default, else the first, else the empty page holds`() {
            var login = lab
            login.macOptions.autoConnectAtLogin = true
            let defaulted = daemonShell([home, cabin, login])
            let first = daemonShell([cabin, home])
            let empty = daemonShell([])
            for shell in [defaulted, first, empty] {
                shell.receive(.unreported, at: date)
                shell.receive(unreachable, at: date)
                shell.routeWindow(.manageTunnels)
            }
            #expect(defaulted.selectedProfileID == login.id)
            #expect(first.selectedProfileID == cabin.id)
            #expect(empty.windowSelection == nil)
            // A daemon reached later, after a reconnect, still gives the first report.
            defaulted.receive(report(cabin.id), at: date)
            #expect(defaulted.selectedProfileID == cabin.id)
        }

        @Test func `a tunnel picked before the first daemon report is kept`() {
            let shell = daemonShell([home, cabin, lab])
            shell.receive(.unreported, at: date)
            shell.windowSelection = .tunnel(lab.id)
            shell.receive(report(cabin.id), at: date)
            #expect(shell.selectedProfileID == lab.id)
            shell.routeWindow(.reopen)
            #expect(shell.selectedProfileID == lab.id)
        }

        @Test(arguments: [false, true])
        func `nothing changes while a command is in flight and the next report settles`(disconnecting: Bool) {
            let shell = daemonShell([home, cabin, lab])
            shell.receive(.unreported, at: date)
            if disconnecting {
                shell.pendingAction = .disconnecting
            } else {
                shell.busy = true
            }
            shell.receive(report(cabin.id), at: date)
            #expect(shell.selectedProfileID == home.id)
            shell.pendingAction = nil
            shell.busy = false
            shell.receive(report(cabin.id), at: date)
            #expect(shell.selectedProfileID == cabin.id)
        }
    }
#endif
