// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    /// SPEC 5.2 and 5.3: the tunnel page's rows, status words and button, read through its presentation.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacTunnelPageTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let generation = Generation(rawValue: 1)
        private let cabin = TunnelProfile(name: "Cabin")

        private enum State: CaseIterable {
            case active, inactive, activating, reconnecting, blocked, signIn, unknown, notProtected
        }

        private func home() throws -> TunnelProfile {
            var profile = TunnelProfile(name: "Home")
            profile.interface.addresses = try [IPAddressRange("10.8.0.2/24"), IPAddressRange("fd00:8::2/64")]
            profile.interface.dns = try [DNSServer("10.8.0.1")]
            profile.interface.mtu = 1420
            profile.peers = try [.init(
                publicKey: profile.interface.publicKey,
                allowedIPs: [.allIPv4],
                endpoint: Endpoint("vpn.example.net:51820"),
                persistentKeepalive: 25,
            )]
            return profile
        }

        private func status(_ state: State, active: UUID?) -> TunnelStatus {
            let expires = date.addingTimeInterval(272)
            let (phase, protection): (TunnelPhase, ProtectionState) = switch state {
            case .active: (.active(generation), .protected)
            case .inactive: (.idle, .unprotected)
            case .activating: (.preparing(generation), .blocked)
            case .reconnecting: (.reasserting(generation, reason: .wake), .blocked)
            case .blocked: (.failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false), .blocked)
            case .signIn: (.captiveWindow(generation, expires: expires), .captiveWindow(expires: expires))
            case .unknown: (.active(generation), .unknown)
            case .notProtected: (.active(generation), .unprotected)
            }
            var status = TunnelStatus(phase: phase, protection: protection, transport: nil, health: .idle, recentEvents: [])
            status.activeProfileID = state == .inactive ? nil : active
            status.measuredAt = date
            return status
        }

        private func shell(_ state: State = .active, profiles: [TunnelProfile]? = nil) throws -> MacShellModel {
            let profiles = try profiles ?? [home(), cabin]
            return MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: profiles,
                status: status(state, active: profiles.first?.id),
                now: date,
            )
        }

        private func sample(_ model: MacShellModel, at seconds: Double, received: UInt64, sent: UInt64 = 0) throws -> TunnelStatistics {
            let key = try #require(model.profiles.first?.interface.publicKey)
            return try TunnelStatistics(
                generation: 1, sampledAt: date.addingTimeInterval(seconds), interfaceName: "utun7", listenPort: nil,
                peers: [.init(
                    publicKey: key, endpoint: Endpoint("203.0.113.7:51820"), lastHandshake: date.addingTimeInterval(-18),
                    rxBytes: received, txBytes: sent, persistentKeepalive: 25,
                )],
            )
        }

        private func page(_ model: MacShellModel, _ index: Int = 0) -> MacTunnelPagePresentation {
            MacTunnelPagePresentation(model: model, profile: model.profiles[index])
        }

        private func rows(_ page: MacTunnelPagePresentation) -> [MacTunnelPagePresentation.Row] {
            page.groups.flatMap(\.rows)
        }

        private func value(_ page: MacTunnelPagePresentation, _ id: String) -> String? {
            rows(page).first { $0.id == id }?.value
        }

        @Test func `groups come in the agreed order with the tunnel name as title`() throws {
            let model = try shell()
            let active = page(model)
            #expect(active.title == "Home")
            #expect(active.groups.map(\.id) == ["traffic", "addresses", "server.0", "protection", "advanced"])
            #expect(active.groups.map(\.title) == ["Traffic", "Addresses", "Server", "Protection", "Advanced"])
            #expect(rows(active).map(\.id) == [
                "download", "upload", "lastHandshake", "tunnelAddress", "ipv6Address", "dns", "routes",
                "peer.0.name", "peer.0.address", "peer.0.publicKey", "peer.0.keepalive",
                "killSwitch", "localNetwork", "exclusions", "onDemand", "startup", "interface", "mtu", "publicKey",
            ])
        }

        private func expected(_ state: State, _ model: MacShellModel) -> (String, String?, String) {
            switch state {
            case .active: ("Active", "Connected for 3 h 12 min", "Deactivate")
            case .inactive: ("Inactive", nil, "Activate")
            case .activating: ("Activating…", "Waiting for the server to answer", "Deactivate")
            case .reconnecting: ("Reconnecting…", "Waiting for the server to answer", "Deactivate")
            case .blocked: ("Traffic blocked", "The tunnel is down, so the kill switch is blocking all traffic.", "Deactivate")
            case .signIn: ("Unprotected for 4:32", "Sign-in window is open", "Deactivate")
            case .unknown: ("Unknown", model.presentation.secondary, "Deactivate")
            case .notProtected: ("Not protected", model.presentation.secondary, "Deactivate")
            }
        }

        private func expectedExtra(_ state: State) -> MacTunnelPagePresentation.Extra? {
            switch state {
            case .blocked: .signIn(note: "Opens 5 minutes without protection so you can reach the sign-in page.")
            case .signIn: .signInOpen
            case .unknown: .serviceNotAnswering
            default: nil
            }
        }

        @Test(arguments: State.allCases)
        private func `status word second line and button follow the state`(_ state: State) throws {
            let model = try shell(state)
            model.recordSessionStart(at: date.addingTimeInterval(-11520))
            let status = page(model).status
            let want = expected(state, model)
            #expect(status.word == want.0)
            #expect(status.detail == want.1)
            #expect(status.buttonTitle == want.2)
            #expect(status.buttonEnabled == (state != .unknown))
            #expect(status.extra == expectedExtra(state))
            // One mapping: the menu's Status line says the same word.
            #expect(MacMenuPresentation(model: model).rows.first?.title == "Status: \(status.word)")
        }

        @Test func `stale reports read Unknown on every page with the button disabled`() throws {
            let model = try shell()
            model.tick(at: date.addingTimeInterval(30))
            for index in 0 ... 1 {
                let status = page(model, index).status
                #expect(status.word == "Unknown")
                #expect(!status.buttonEnabled)
                #expect(status.extra == .serviceNotAnswering)
            }
            #expect(page(model).groups.first?.id == "addresses")
        }

        @Test func `idle unprotected reads Inactive and a pending start names itself`() throws {
            let model = try shell(.inactive)
            #expect(page(model).status.word == "Inactive")
            #expect(page(model).status.buttonTitle == "Activate")
            model.pendingAction = .connecting(cabin.id)
            let pending = page(model, 1).status
            #expect(pending.word == "Activating…")
            #expect(pending.detail == model.pendingActionText)
            #expect(!pending.buttonEnabled)
            #expect(page(model).status.detail == nil)
            #expect(model.sidebarState(cabin) == "Activating…")
        }

        @Test func `the sign-in offer follows the sign-in window setting`() throws {
            let model = try shell(.blocked)
            model.preferences.global.captiveWindowSeconds = 60
            #expect(page(model).status.extra == .signIn(note: "Opens 1 minute without protection so you can reach the sign-in page."))
            model.preferences.global.captiveWindowSeconds = 600
            #expect(page(model).status.extra == .signIn(note: "Opens 10 minutes without protection so you can reach the sign-in page."))
        }

        @Test func `Lockdown blocking with no active tunnel offers Activate and Sign In`() throws {
            let model = try shell(.inactive)
            var lockdown = TunnelStatus(phase: .idle, protection: .blocked, transport: nil, health: .idle, recentEvents: [])
            lockdown.measuredAt = date
            model.receive(lockdown, at: date)
            #expect(model.activeProfileID == nil)
            let status = page(model).status
            #expect(status.word == "Traffic blocked")
            #expect(status.buttonTitle == "Activate")
            #expect(status.buttonEnabled)
            #expect(status.extra == .signIn(note: "Opens 5 minutes without protection so you can reach the sign-in page."))
            #expect(page(model).groups.first?.id == "addresses")
            #expect(model.killSwitchWord(for: model.profiles[0]) == "Blocking")
        }

        @Test func `another tunnel's page reads Inactive with no live rows and no zeros`() throws {
            let model = try shell()
            try model.receiveStatistics(sample(model, at: -2, received: 100))
            try model.receiveStatistics(sample(model, at: 0, received: 1100))
            let other = page(model, 1)
            #expect(other.status.word == "Inactive")
            #expect(other.status.detail == nil)
            #expect(other.status.buttonTitle == "Activate")
            #expect(other.groups.map(\.id) == ["protection", "advanced"])
            #expect(other.groups.allSatisfy { $0.id != "traffic" })
            #expect(value(other, "killSwitch") == "Off")
            let inactive = try page(shell(.inactive))
            for page in [other, inactive] {
                #expect(!rows(page).contains { ["download", "upload", "lastHandshake", "interface", "peer.0.address"].contains($0.id) })
                #expect(!rows(page).contains { $0.value == "0" || $0.value.hasPrefix("0 ") })
            }
        }

        @Test func `blocked keeps the handshake and one unavailable transfer row`() throws {
            let model = try shell(.blocked)
            let traffic = try #require(page(model).groups.first)
            #expect(traffic.id == "traffic")
            #expect(traffic.rows.map(\.label) == ["Last handshake", "Download and upload"])
            #expect(traffic.rows.map(\.value) == ["Unavailable", "Unavailable"])
            #expect(value(page(model), "interface") == nil)
            #expect(value(page(model), "killSwitch") == "Blocking")
        }

        @Test func `an active tunnel without a session start or sample says Unavailable instead of hiding lines`() throws {
            // The app first observes a tunnel that was already up: no recorded start and no statistics yet.
            let model = try shell()
            #expect(model.traffic.startedAt == nil)
            let active = page(model)
            #expect(active.status.word == "Active")
            #expect(active.status.detail == "Connected for Unavailable")
            for id in ["download", "upload", "lastHandshake", "peer.0.address", "interface"] {
                #expect(value(active, id) == "Unavailable", "\(id)")
            }
        }

        @Test func `rates are the measured byte delta, never the service's zero`() throws {
            let model = try shell()
            #expect(model.status.health.rxRate == 0)
            #expect(value(page(model), "download") == "Unavailable")
            try model.receiveStatistics(sample(model, at: -2, received: 100, sent: 50))
            try model.receiveStatistics(sample(model, at: 0, received: 1100, sent: 250))
            let active = page(model)
            #expect(value(active, "download") == "500 B/s · 1.1 kB")
            #expect(value(active, "upload") == "100 B/s · 250 B")
            #expect(value(active, "lastHandshake") == "18 seconds ago")
            #expect(value(active, "peer.0.address") == "203.0.113.7:51820")
            #expect(value(active, "interface") == "utun7")
            // A sample older than 2.5 intervals is no longer live.
            model.tick(at: date.addingTimeInterval(6))
            #expect(value(page(model), "interface") == "Unavailable")
        }
    }

    /// Saved rows, keys, protection words and the source checks.
    extension MacTunnelPageTests {
        @Test private func `saved rows omit what is not configured`() throws {
            var bare = try home()
            bare.interface.addresses = try [IPAddressRange("10.8.0.2/32")]
            bare.interface.dns = []
            bare.interface.mtu = nil
            bare.peers[0].persistentKeepalive = nil
            bare.peers[0].endpoint = nil
            bare.peers[0].allowedIPs = try [IPAddressRange("10.8.0.0/24"), IPAddressRange("192.168.1.0/24")]
            let model = try shell(.inactive, profiles: [bare])
            let saved = page(model)
            #expect(rows(saved).map(\.id) == [
                "tunnelAddress", "routes", "peer.0.publicKey", "killSwitch", "localNetwork", "exclusions", "onDemand", "startup", "mtu",
                "publicKey",
            ])
            #expect(value(saved, "mtu") == "Automatic")
            #expect(value(saved, "routes") == "2 routes")
            #expect(saved.routes == ["10.8.0.0/24", "192.168.1.0/24"])
            #expect(value(saved, "startup") == "Never")
            #expect(value(saved, "onDemand") == "Off")
            #expect(value(saved, "localNetwork") == "Allowed")
            let full = try page(shell(.inactive))
            #expect(value(full, "routes") == "All traffic")
            #expect(value(full, "peer.0.keepalive") == "Every 25 seconds")
            #expect(value(full, "peer.0.name") == "vpn.example.net")
        }

        @Test private func `several servers repeat the group with numbered titles`() throws {
            var profile = try home()
            let second = try PublicKey(rawValue: Data(repeating: 1, count: 32))
            try profile.peers.append(.init(publicKey: second, allowedIPs: [IPAddressRange("10.9.0.0/16")]))
            let model = try shell(.inactive, profiles: [profile])
            let servers = page(model).groups.filter { $0.id.hasPrefix("server.") }
            #expect(servers.map(\.title) == ["Server 1", "Server 2"])
            #expect(servers[1].rows.map(\.id) == ["peer.1.publicKey"])
            #expect(page(model).routes == ["0.0.0.0/0", "10.9.0.0/16"])
        }

        @Test private func `an empty tunnel has no address rows, no server and no routes`() throws {
            let model = try shell(.inactive, profiles: [TunnelProfile(name: "Empty")])
            let empty = page(model)
            #expect(empty.groups.map(\.id) == ["protection", "advanced"])
            #expect(empty.status.buttonTitle == "Activate")
            #expect(empty.status.buttonEnabled)
        }

        @Test private func `keys are shortened on screen, copied in full, and the private key is absent`() throws {
            let model = try shell()
            let key = model.profiles[0].interface.publicKey.base64
            let row = try #require(rows(page(model)).first { $0.id == "publicKey" })
            #expect(row.label == "This Mac's public key")
            #expect(row.value == "\(key.prefix(6))…\(key.suffix(4))")
            #expect(row.copyValue == key)
            #expect(row.monospaced)
            #expect(rows(page(model)).allSatisfy { !$0.label.localizedCaseInsensitiveContains("private") })
            #expect(rows(page(model)).allSatisfy { $0.link != nil || $0.value == $0.copyValue || $0.monospaced })
        }

        @Test private func `protection rows report state and lead to their pages`() throws {
            var profile = try home()
            profile.macOptions.autoConnectAtLogin = true
            profile
                .onDemand = try #require(MacOnDemandForm(ethernet: false, wifi: true, match: .except, networks: [.init(name: "Cafe")])
                    .policy)
            let model = try shell(profiles: [profile])
            model.preferences.global.allowLAN = false
            let protection = try #require(page(model).groups.first { $0.id == "protection" })
            #expect(protection.rows.map(\.value) == ["On", "Not allowed", "None", "Wi-Fi, except 1 network", "When I log in"])
            #expect(protection.rows.map(\.link) == [.protectionPage, .protectionPage, nil, .onDemand, .startup])
            #expect(MacStartupOption.allCases.map(\.pageWord) == ["Never", "When I log in", "At start-up"])
        }

        @Test private func `the kill switch word follows protection on this tunnel's page`() throws {
            let cases: [(State, String)] = [
                (.active, "On"), (.blocked, "Blocking"), (.signIn, "Paused"), (.inactive, "Off"), (.unknown, "Unavailable"),
            ]
            for (state, word) in cases {
                let model = try shell(state)
                #expect(model.killSwitchWord(for: model.profiles[0]) == word)
                #expect(model.killSwitchWord(for: nil) == word)
            }
        }

        @Test private func `durations read in hours and minutes and handshakes in words`() {
            #expect(MacTunnelPagePresentation.connectedDuration(date.addingTimeInterval(-45), now: date) == "45 s")
            #expect(MacTunnelPagePresentation.connectedDuration(date.addingTimeInterval(-720), now: date) == "12 min")
            #expect(MacTunnelPagePresentation.connectedDuration(date.addingTimeInterval(-11520), now: date) == "3 h 12 min")
            #expect(MacTunnelPagePresentation.connectedDuration(date.addingTimeInterval(-187_200), now: date) == "2 d 4 h")
            #expect(MacTunnelPagePresentation.longAgo(date.addingTimeInterval(-1), now: date) == "1 second ago")
            #expect(MacTunnelPagePresentation.longAgo(date.addingTimeInterval(-60), now: date) == "1 minute ago")
            #expect(MacTunnelPagePresentation.longAgo(date.addingTimeInterval(-7200), now: date) == "2 hours ago")
        }

        @Test private func `the Mac page uses no orb, tiles, chart or activation switch`() throws {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
            for file in ["MacStatusViews.swift", "MacTunnelPage.swift"] {
                let source = try String(contentsOf: directory.appending(path: file), encoding: .utf8)
                for banned in ["ConnectionOrb", "StatTile", "MacSessionChart", "Toggle(", "StateChip", "Image(systemName: state"] {
                    #expect(!source.contains(banned), "\(banned) in \(file)")
                }
            }
            #expect(!FileManager.default.fileExists(atPath: directory.appending(path: "MacSessionChart.swift").path))
            let page = try String(contentsOf: directory.appending(path: "MacTunnelPage.swift"), encoding: .utf8)
            #expect(page.contains("await model.toggleMenuTunnel(profile.id)"))
            #expect(!page.contains("toggleConnection"))
            #expect(page.contains("model.activationBlocker"))
        }
    }
#endif
