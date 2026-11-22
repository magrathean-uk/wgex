// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    /// Joins between M07-T03 (tunnel page, window), M07-T04 (sheets, activation guard, delete) and M07-T05 (app pages) that
    /// no single task could test on its own branch.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacStackJoinTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)

        private func complete(_ name: String) throws -> TunnelProfile {
            var profile = TunnelProfile(name: name)
            profile.interface.addresses = try [IPAddressRange("10.8.0.2/24")]
            profile.peers = try [.init(
                publicKey: profile.interface.publicKey, allowedIPs: [.allIPv4], endpoint: Endpoint("vpn.example.net:51820"),
            )]
            return profile
        }

        private func shell(_ profiles: [TunnelProfile], status: TunnelStatus = .idle) -> MacShellModel {
            var status = status
            status.measuredAt = date
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: profiles,
                status: status,
                now: date,
            )
            model.refusesIncompleteTunnels = true
            return model
        }

        @Test func `the page disables Activate for a tunnel saved without an address or a server`() throws {
            let empty = TunnelProfile(name: "Empty")
            let home = try complete("Home")
            let model = shell([empty, home])
            let blocked = MacTunnelPagePresentation(model: model, profile: empty).status
            #expect(blocked.buttonTitle == MacStrings.activate)
            #expect(!blocked.buttonEnabled)
            #expect(model.activationBlocker(empty) == MacStrings.activationNeedsAddressAndServer)
            let ready = MacTunnelPagePresentation(model: model, profile: home).status
            #expect(ready.buttonTitle == MacStrings.activate)
            #expect(ready.buttonEnabled)
            #expect(model.activationBlocker(home) == nil)
        }

        @Test func `the page never blocks Deactivate`() throws {
            let home = try complete("Home")
            var status = TunnelStatus(
                phase: .active(Generation(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: [],
            )
            status.activeProfileID = home.id
            let model = shell([home, TunnelProfile(name: "Empty")], status: status)
            let page = MacTunnelPagePresentation(model: model, profile: home).status
            #expect(page.buttonTitle == MacStrings.deactivate)
            #expect(page.buttonEnabled)
        }

        @Test func `the page and window use T04's blocker, delete alert, sheets and empty window`() throws {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let mac = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
            func read(_ url: URL) throws -> String {
                try String(contentsOf: url, encoding: .utf8)
            }
            let page = try read(mac.appending(path: "MacTunnelPage.swift"))
            #expect(page.contains("let blocker = model.activationBlocker(profile)"))
            let window = try read(mac.appending(path: "MacStatusViews.swift"))
            // Empty window: T04's centred page alone, with no protection panel under it (SPEC 6.5).
            #expect(window.contains("MacEmptyTunnelsView(model: model, addProfile: addProfile, paste: paste)"))
            #expect(!window.contains("MacProtectionPanel"))
            // Delete Tunnel… on the page and in the sidebar goes through the one alert, which deletes deactivate-first.
            #expect(window.contains("MacTunnelPage(model: model, profile: profile, edit: edit, export: export) { pendingDeletion = $0 }"))
            #expect(window.contains(".macDeleteTunnelAlert(model: model, pending: $pendingDeletion)"))
            let alert = try read(mac.appending(path: "MacDeleteTunnelAlert.swift"))
            #expect(alert.contains("await model.deleteProfile(profile)"))
            #expect(alert.contains("model.deletionDeactivatesFirst(profile)"))
            // Edit… and Export… open T04's Edit sheet and the export sheet hosted by the app.
            let app = try read(root.appending(path: "Apps/WGEXMac/WGEXMacApp.swift"))
            #expect(app.contains("edit: model.openEditor,"))
            #expect(app.contains("export: model.openExport,"))
            #expect(app.contains("MacTunnelEditSheet("))
            #expect(app.contains("ExportSheet(model: export)"))
        }
    }
#endif
