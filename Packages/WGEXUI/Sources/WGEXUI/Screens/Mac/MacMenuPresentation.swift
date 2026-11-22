// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// Plain menu rows, with stable identities so AppKit can update an open menu in place.
    public struct MacMenuPresentation {
        public enum Command: Equatable {
            case tunnel(UUID), signIn, endSignIn, open, manage, importFile, about, quit
        }

        public struct Row {
            public let id: String
            public var title: String
            public var command: Command?
            public var enabled = false
            public var checked = false
            public var indentation = 0
            public var separator = false
        }

        public private(set) var rows: [Row] = []

        public init(model: MacShellModel) {
            let verdict = model.presentation.verdict
            let unknown = verdict == .unknown || verdict == .stale
            let state = model.tunnelState.word(now: model.now)
            rows.append(Row(id: "status", title: MacStrings.menuStatus(state)))
            let available = !model.hostGuarded && !model.busy && model.pendingAction == nil
            if unknown {
                rows.append(Row(id: "reason", title: MacStrings.menuServiceUnavailable))
                action("stateAction", MacStrings.menuOpenWGEX, .open)
            } else if verdict == .blocked {
                rows.append(Row(id: "reason", title: MacStrings.menuBlocked))
                action("stateAction", MacStrings.menuSignIn, .signIn, enabled: available && model.showsCaptiveButton)
            } else if verdict == .captiveWindow {
                rows.append(Row(id: "reason", title: MacStrings.menuSignInOpen))
                action("stateAction", MacStrings.menuEndSignIn, .endSignIn, enabled: available)
            }
            divider("tunnels")
            for profile in model.profiles {
                let ticked = !unknown && verdict != .inactive && state != MacStrings.inactive && profile.id == model.activeProfileID
                rows.append(Row(
                    id: profile.id.uuidString,
                    title: profile.name,
                    command: .tunnel(profile.id),
                    enabled: !unknown && available,
                    checked: ticked,
                ))
                if ticked, verdict == .protected {
                    details(profile, model: model)
                } else if ticked, verdict == .connecting || verdict == .reasserting {
                    detail("endpoint", MacStrings.endpoint, MacLiveTunnelValues.pendingEndpoint(profile, sample: model.liveSample))
                    rows.append(Row(id: "waiting", title: MacStrings.menuWaiting, indentation: 1))
                }
            }
            divider("management")
            action("manage", MacStrings.manageTunnels, .manage)
            action("import", MacStrings.importTunnelsFromFile, .importFile)
            divider("app")
            action("about", MacStrings.aboutWGEX, .about)
            action("quit", MacStrings.quitWGEX, .quit)
        }

        private mutating func action(_ id: String, _ title: String, _ command: Command, enabled: Bool = true) {
            rows.append(Row(id: id, title: title, command: command, enabled: enabled))
        }

        private mutating func divider(_ id: String) {
            rows.append(Row(id: id, title: "", separator: true))
        }

        private mutating func detail(_ id: String, _ label: String, _ value: String) {
            rows.append(Row(id: id, title: MacStrings.menuDetail(label, value), indentation: 1))
        }

        private mutating func details(_ profile: TunnelProfile, model: MacShellModel) {
            let sample = model.liveSample
            detail("interface", MacStrings.menuInterface, sample?.interfaceName ?? MacStrings.unavailable)
            let addresses = profile.interface.addresses
            let v4 = addresses.filter { !$0.isIPv6 }.map(\.address)
            let v6 = addresses.filter(\.isIPv6).map(\.address)
            if !v4.isEmpty {
                detail("address", MacStrings.menuAddress, v4.joined(separator: ", "))
            }
            if !v6.isEmpty {
                detail("ipv6", MacStrings.menuIPv6Address, v6.joined(separator: ", "))
            }
            if !profile.interface.dns.isEmpty {
                detail("dns", MacStrings.dns, profile.interface.dns.map(\.stringRepresentation).joined(separator: ", "))
            }
            if profile.peers.contains(where: { $0.endpoint != nil }) || sample?.peers.contains(where: { $0.endpoint != nil }) == true {
                detail("endpoint", MacStrings.endpoint, MacLiveTunnelValues.liveEndpoint(profile, sample: sample))
            }
            if let mtu = profile.interface.mtu {
                detail("mtu", MacStrings.mtu, String(mtu))
            }
            let handshake = MacLiveTunnelValues.handshake(sample)
            detail("handshake", MacStrings.menuHandshake, handshake.map { UIFormat.ago($0, now: model.now) } ?? MacStrings.unavailable)
            let rates = model.liveRates(sample)
            detail(
                "download",
                MacStrings.download,
                MacStrings.menuTransfer(rate: rates?.download, total: MacLiveTunnelValues.total(sample, received: true)),
            )
            detail(
                "upload",
                MacStrings.upload,
                MacStrings.menuTransfer(rate: rates?.upload, total: MacLiveTunnelValues.total(sample, received: false)),
            )
            detail("killSwitch", MacStrings.menuKillSwitch, MacStrings.menuKillSwitchOn)
        }
    }
#endif
