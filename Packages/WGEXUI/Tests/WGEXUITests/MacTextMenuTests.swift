// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacTextMenuTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let generation = Generation(rawValue: 1)

        private enum State: CaseIterable {
            case active, inactive, activating, reconnecting, blocked, signIn, unknown
        }

        private func profile() throws -> TunnelProfile {
            var profile = TunnelProfile(name: "Home")
            profile.interface.addresses = try [IPAddressRange("10.8.0.2/24"), IPAddressRange("fd00:8::2/64")]
            profile.interface.dns = try [DNSServer("10.8.0.1"), DNSServer("fd00:8::1")]
            profile.interface.mtu = 1420
            profile.peers = try [.init(
                publicKey: profile.interface.publicKey,
                allowedIPs: [.allIPv4],
                endpoint: Endpoint("saved.example:51820"),
            )]
            return profile
        }

        private func phase(_ state: State) -> TunnelPhase {
            switch state {
            case .active, .unknown: .active(generation)
            case .inactive: .idle
            case .activating: .preparing(generation)
            case .reconnecting: .reasserting(generation, reason: .wake)
            case .blocked: .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false)
            case .signIn: .captiveWindow(generation, expires: date.addingTimeInterval(272))
            }
        }

        private func protection(_ state: State) -> ProtectionState {
            switch state {
            case .active: .protected
            case .inactive, .activating, .reconnecting: .unprotected
            case .blocked: .blocked
            case .signIn: .captiveWindow(expires: date.addingTimeInterval(272))
            case .unknown: .unknown
            }
        }

        private func shell(_ state: State = .active, backend: FakeTunnelBackend = FakeTunnelBackend()) throws -> MacShellModel {
            let profile = try profile()
            var status = TunnelStatus(phase: phase(state), protection: protection(state), transport: nil, health: .idle, recentEvents: [])
            status.activeProfileID = state == .inactive ? nil : profile.id
            status.measuredAt = date
            return MacShellModel(
                dependencies: .init(backend: backend, service: FakeServiceController(), simulated: true),
                profiles: [profile, TunnelProfile(name: "Cabin")],
                status: status,
                now: date,
            )
        }

        private func sample(_ model: MacShellModel, at seconds: Double, received: UInt64, sent: UInt64 = 0) throws -> TunnelStatistics {
            let key = try #require(model.profiles.first?.interface.publicKey)
            return try TunnelStatistics(
                generation: 1,
                sampledAt: date.addingTimeInterval(seconds),
                interfaceName: "utun7",
                listenPort: nil,
                peers: [.init(
                    publicKey: key,
                    endpoint: Endpoint("203.0.113.7:51820"),
                    lastHandshake: date.addingTimeInterval(-18),
                    rxBytes: received,
                    txBytes: sent,
                    persistentKeepalive: nil,
                )],
            )
        }

        private func expectedTitle(_ state: State) -> String {
            switch state {
            case .active: "Status: Active"
            case .inactive: "Status: Inactive"
            case .activating: "Status: Activating…"
            case .reconnecting: "Status: Reconnecting…"
            case .blocked: "Status: Traffic blocked"
            case .signIn: "Status: Unprotected for 4:32"
            case .unknown: "Status: Unknown"
            }
        }

        @Test(arguments: State.allCases)
        private func `every menu state is native text with the same footer`(_ state: State) throws {
            let model = try shell(state)
            try model.receiveStatistics(sample(model, at: 0, received: 1200))
            let controller = MacTextMenuController(model: model, now: { date }, perform: { _ in })
            let items = controller.menu.items
            #expect(items.first?.title == expectedTitle(state))
            #expect(items.first?.isEnabled == false)
            #expect(items.first?.action == nil)
            #expect(items.allSatisfy { $0.view == nil && $0.image == nil && $0.submenu == nil })
            #expect(items.suffix(5).filter { !$0.isSeparatorItem }.map(\.title) ==
                ["Manage Tunnels…", "Import Tunnels from File…", "About WGEX", "Quit WGEX"])
            #expect(items.last?.keyEquivalent == "q")
            #expect(items.last?.keyEquivalentModifierMask == .command)
            let tunnels = items.filter { ["Home", "Cabin"].contains($0.title) }
            #expect(tunnels.map(\.title) == ["Home", "Cabin"])
            #expect(tunnels.first?.state == (state == .inactive || state == .unknown ? .off : .on))
            #expect(tunnels.allSatisfy(\.isEnabled) == (state != .unknown))
            let details = items.filter { $0.indentationLevel == 1 }
            #expect(details.count == (state == .active ? 10 : state == .activating || state == .reconnecting ? 2 : 0))
            #expect(details.allSatisfy { !$0.isEnabled && $0.action == nil })
            let action = items.first { $0.identifier?.rawValue == "stateAction" }
            switch state {
            case .blocked: #expect(action?.title == "Sign In to This Network…")
            case .signIn: #expect(action?.title == "End Sign-In Now")
            case .unknown: #expect(action?.title == "Open WGEX…")
            default: #expect(action == nil)
            }
        }

        @Test func `active details use measured endpoint saved configuration and app rates`() throws {
            let model = try shell()
            try model.receiveStatistics(sample(model, at: -2, received: 1000, sent: 100))
            try model.receiveStatistics(sample(model, at: 0, received: 3000, sent: 300))
            // Browsing another tunnel in the window must not steal the menu's active statistics.
            model.selectedProfileID = model.profiles.last?.id
            let rows = MacMenuPresentation(model: model).rows.filter { $0.indentation == 1 }
            #expect(rows.map(\.title) == [
                "Interface: utun7", "Address: 10.8.0.2", "IPv6 Address: fd00:8::2", "DNS: 10.8.0.1, fd00:8::1",
                "Endpoint: 203.0.113.7:51820", "MTU: 1420", "Handshake: 18 s ago",
                "Download: 1.0 kB/s (3.0 kB)", "Upload: 100 B/s (300 B)", "Kill Switch: On",
            ])
        }

        @Test(arguments: [State.activating, .reconnecting])
        private func `activating shows the saved endpoint until a measured address arrives`(_ state: State) throws {
            let model = try shell(state)
            #expect(MacMenuPresentation(model: model).rows.filter { $0.indentation == 1 }.map(\.title) ==
                ["Endpoint: saved.example:51820", "Waiting for the server to answer"])
            try model.receiveStatistics(sample(model, at: 0, received: 0))
            #expect(MacMenuPresentation(model: model).rows.contains { $0.title == "Endpoint: 203.0.113.7:51820" })
            let empty = try shell(state)
            empty.profiles[0].peers[0].endpoint = nil
            #expect(MacMenuPresentation(model: empty).rows.contains { $0.title == "Endpoint: Unavailable" })
        }

        @Test func `absent configuration is omitted and missing live values say unavailable`() throws {
            let model = try shell()
            model.profiles[0].interface.addresses = try [IPAddressRange("10.8.0.2"), IPAddressRange("10.8.0.3")]
            model.profiles[0].interface.dns = []
            model.profiles[0].interface.mtu = nil
            let rows = MacMenuPresentation(model: model).rows
            #expect(!rows.contains { ["ipv6", "dns", "mtu"].contains($0.id) })
            #expect(rows.contains { $0.title == "Address: 10.8.0.2, 10.8.0.3" })
            #expect(rows.contains { $0.title == "Endpoint: Unavailable" })
            #expect(rows.contains { $0.title == "Download: Unavailable (Unavailable)" })
            #expect(!rows.contains { $0.title.contains("saved.example") })
        }

        @Test func `refresh timer updates the open menu in place and stops on close`() throws {
            let model = try shell()
            var now = date
            var fire: (@MainActor () -> Void)?
            var cancelled = 0
            var visibility: [Bool] = []
            let controller = MacTextMenuController(model: model, now: { now }, schedule: { interval, callback in
                #expect(interval == 2)
                fire = callback
                return { cancelled += 1 }
            }, visibility: { visibility.append($0) }, perform: { _ in })
            controller.menuWillOpen(controller.menu)
            controller.menuWillOpen(controller.menu)
            let item = try #require(controller.menu.items.first { $0.identifier?.rawValue == "download" })
            try model.receiveStatistics(sample(model, at: 0, received: 1000))
            try model.receiveStatistics(sample(model, at: 2, received: 5000))
            now = date.addingTimeInterval(2)
            fire?()
            #expect(controller.menu.items.contains { $0 === item })
            #expect(item.title == "Download: 2.0 kB/s (5.0 kB)")
            now = date.addingTimeInterval(8)
            fire?()
            #expect(item.title == "Download: Unavailable (Unavailable)")
            now = date.addingTimeInterval(30)
            fire?()
            #expect(controller.menu.items.first?.title == "Status: Unknown")
            #expect(!controller.menu.items.contains { $0.indentationLevel == 1 || $0.state == .on })
            controller.menuDidClose(controller.menu)
            #expect(cancelled == 1)
            #expect(visibility == [true, false])
            #expect(!controller.isOpen)
            let closedTitle = controller.menu.items.first?.title
            now = date
            fire?()
            #expect(controller.menu.items.first?.title == closedTitle)
            controller.menuWillOpen(controller.menu)
            controller.menuDidClose(controller.menu)
            #expect(cancelled == 2)
        }

        @Test func `native timer fires in the event tracking run loop and cancellation stops it`() {
            var fires = 0
            let cancel = MacTextMenuController.timer(interval: 0.01) { fires += 1 }
            let deadline = Date().addingTimeInterval(1)
            while fires == 0, Date() < deadline {
                _ = RunLoop.main.run(mode: .eventTracking, before: deadline)
            }
            #expect(fires > 0)
            cancel()
            let count = fires
            _ = RunLoop.main.run(mode: .eventTracking, before: Date().addingTimeInterval(0.03))
            #expect(fires == count)
        }

        @Test func `sign in countdown refreshes and unknown recovers without reopening`() throws {
            let model = try shell(.signIn)
            var now = date
            let controller = MacTextMenuController(model: model, now: { now }, perform: { _ in })
            now = date.addingTimeInterval(2)
            controller.refresh()
            #expect(controller.menu.items.first?.title == "Status: Unprotected for 4:30")
            model.receiveConnection(.disconnected(lastError: nil))
            controller.refresh()
            #expect(controller.menu.items.first?.title == "Status: Unknown")
            var status = model.status
            status.phase = .active(generation)
            status.protection = .protected
            status.measuredAt = now
            model.receive(status, at: now)
            controller.refresh()
            #expect(controller.menu.items.first?.title == "Status: Active")
        }

        @Test func `native state actions and footer dispatch the named commands`() throws {
            _ = NSApplication.shared
            for (state, expected) in [(State.blocked, MacMenuPresentation.Command.signIn), (.signIn, .endSignIn), (.unknown, .open)] {
                let model = try shell(state)
                var commands: [MacMenuPresentation.Command] = []
                let controller = MacTextMenuController(model: model, now: { date }, perform: { commands.append($0) })
                let action = try #require(controller.menu.items.firstIndex { $0.identifier?.rawValue == "stateAction" })
                controller.menu.performActionForItem(at: action)
                #expect(commands == [expected])
                for id in ["manage", "import", "about", "quit"] {
                    let index = try #require(controller.menu.items.firstIndex { $0.identifier?.rawValue == id })
                    controller.menu.performActionForItem(at: index)
                }
                #expect(Array(commands.suffix(4)) == [.manage, .importFile, .about, .quit])
            }
        }

        @Test func `native item dispatch rejects disabled and newly unknown tunnels`() throws {
            _ = NSApplication.shared
            let model = try shell()
            var commands: [MacMenuPresentation.Command] = []
            let controller = MacTextMenuController(model: model, now: { date }, perform: { commands.append($0) })
            let index = try #require(controller.menu.items.firstIndex { $0.title == "Home" })
            controller.menu.performActionForItem(at: index)
            #expect(commands == [.tunnel(model.profiles[0].id)])
            model.receiveConnection(.disconnected(lastError: nil))
            controller.menu.performActionForItem(at: index)
            #expect(commands.count == 1)
        }

        @Test func `an unticked on demand tunnel is explicitly activated by the standard menu`() async throws {
            let backend = FakeTunnelBackend()
            let model = try shell(.inactive, backend: backend)
            model.profiles[0].onDemand = .interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"])))
            let id = model.profiles[0].id
            await model.toggleMenuTunnel(id)
            #expect(backend.calls.contains(.install(id)))
            #expect(backend.calls.contains(.start(id, transport: nil)))
            #expect(model.operationMessage == nil)
        }
    }

    private extension MacTextMenuTests {
        @Test func `ticked tunnel deactivates and another tunnel stops the previous first`() async throws {
            let backend = FakeTunnelBackend()
            let model = try shell(backend: backend)
            let first = model.profiles[0]
            let second = model.profiles[1]
            model.daemonHooks.stopCurrent = { try await backend.stop(first.id) }
            await model.toggleMenuTunnel(first.id)
            #expect(backend.calls.contains(.stop(first.id)))
            await model.toggleMenuTunnel(second.id)
            let stop = try #require(backend.calls.lastIndex(of: .stop(first.id)))
            let start = try #require(backend.calls.firstIndex(of: .start(second.id, transport: nil)))
            #expect(stop < start)
            model.receiveConnection(.disconnected(lastError: nil))
            let count = backend.calls.count
            await model.toggleMenuTunnel(first.id)
            #expect(backend.calls.count == count)
        }
    }
#endif
