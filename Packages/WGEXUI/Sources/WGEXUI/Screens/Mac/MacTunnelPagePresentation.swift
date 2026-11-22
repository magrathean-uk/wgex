// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// The tunnel page as plain rows (SPEC 5.2, 5.3), built from the shell so tests read it without a view. Saved rows
    /// always show; live rows show only while this tunnel is up, and a missing live value says "Unavailable".
    public struct MacTunnelPagePresentation: Equatable {
        /// The extra row in the status group (SPEC 5.3).
        public enum Extra: Equatable, Sendable {
            /// Blocked: offer the sign-in window, with the minutes from the Sign-in window setting.
            case signIn(note: String)
            /// The sign-in window is open: offer to end it.
            case signInOpen
            /// Unknown: lead to the Background Service page.
            case serviceNotAnswering
        }

        public typealias Link = TunnelPageLink
        public typealias Row = TunnelPageRow
        public typealias Group = TunnelPageGroup

        public struct Status: Equatable, Sendable {
            public let state: MacTunnelState
            public let word: String
            /// The second line; nil for Inactive (SPEC E5).
            public let detail: String?
            /// The app's recovery and reporter lines, when the page shows the app's state.
            public let reason: String?
            public let reporter: String?
            /// "Activate" or "Deactivate", never an on-demand title (D1).
            public let buttonTitle: String
            public let buttonEnabled: Bool
            public let extra: Extra?
        }

        public let title: String
        public let status: Status
        /// Groups after the status group, in SPEC 5.2 order: Traffic, Addresses, Server, Protection (with Exclusions, DEC-087),
        /// Advanced.
        public let groups: [Group]
        /// Every route over all servers, for the Routes sheet.
        public let routes: [String]
        /// Every exclusion in the core's spelling, for the Exclusions sheet.
        public let exclusions: [String]

        public init(model: MacShellModel, profile: TunnelProfile) {
            title = profile.name
            let state = model.tunnelState(for: profile)
            let isActive = model.activeProfileID == profile.id
            let up = isActive && state.isUp
            let sample = up || (isActive && state == .blocked) ? model.liveSample : nil
            status = Self.status(model: model, profile: profile, state: state)
            routes = TunnelPageRows.uniqueRoutes(profile)
            exclusions = profile.exclusions.entries.map(\.text)
            var groups: [Group] = []
            if up {
                groups.append(Self.traffic(model: model, sample: sample))
            } else if isActive, state == .blocked {
                groups.append(Group(id: "traffic", title: MacStrings.trafficGroup, rows: [
                    TunnelPageRows.handshakeRow(sample, now: model.now),
                    Row("transfer", MacStrings.downloadAndUpload, MacStrings.unavailable),
                ]))
            }
            let addresses = TunnelPageRows.addresses(profile, routes: routes)
            if !addresses.isEmpty {
                groups.append(Group(id: "addresses", title: MacStrings.addresses, rows: addresses))
            }
            for (index, peer) in profile.peers.enumerated() {
                let title = profile.peers.count == 1 ? MacStrings.serverGroup : MacStrings.serverNumber(index + 1)
                let rows = TunnelPageRows.server(peer, index: index, up: up, sample: sample)
                groups.append(Group(id: "server.\(index)", title: title, rows: rows))
            }
            groups.append(Group(id: "protection", title: MacStrings.protection, rows: [
                Row("killSwitch", MacStrings.killSwitch, model.killSwitchWord(for: profile), link: .protectionPage),
                Row(
                    "localNetwork", MacStrings.localNetwork,
                    model.preferences.global.allowLAN ? MacStrings.localNetworkAllowed : MacStrings.localNetworkNotAllowed,
                    link: .protectionPage,
                ),
                TunnelPageRows.exclusionsRow(exclusions),
                Row("onDemand", MacStrings.connectOnDemand, Self.onDemandSummary(profile.onDemand), link: .onDemand),
                Row("startup", MacStrings.connectAutomatically, MacStartupOption(options: profile.macOptions).pageWord, link: .startup),
            ], note: up ? Self.unresolvedNote(model.status.unresolvedExclusions) : nil))
            var advanced: [Row] = []
            if up {
                advanced.append(Row("interface", MacStrings.interface, sample?.interfaceName ?? MacStrings.unavailable))
            }
            advanced.append(Row("mtu", MacStrings.mtu, profile.interface.mtu.map(String.init) ?? MacStrings.automatic))
            advanced.append(TunnelPageRows.keyRow("publicKey", MacStrings.thisMacsPublicKey, profile.interface.publicKey))
            groups.append(Group(id: "advanced", title: MacStrings.advancedGroup, rows: advanced))
            self.groups = groups
        }

        // MARK: Status

        private static func status(model: MacShellModel, profile: TunnelProfile, state: MacTunnelState) -> Status {
            var detail = detailLine(model: model, state: state)
            if isPending(model, for: profile), let pending = model.pendingActionText {
                detail = pending
            }
            let ownsState = model.activeProfileID == nil || model.activeProfileID == profile.id || state == .unknown
            let showsApp = state != .inactive && ownsState
            let activates = model.activeProfileID != profile.id
            // DEC-088: a tunnel saved without an address or a server blocks only Activate; the page says why under the status row.
            let enabled = state != .unknown && !model.busy && model.pendingAction == nil && !model.hostGuarded
                && (!activates || model.canActivate(profile))
            return Status(
                state: state,
                word: state.word(now: model.now),
                detail: detail,
                reason: showsApp ? model.presentation.recoveryDetail : nil,
                reporter: showsApp ? model.presentation.reporterDetail : nil,
                buttonTitle: activates ? MacStrings.activate : MacStrings.deactivate,
                buttonEnabled: enabled,
                extra: extra(model: model, state: state),
            )
        }

        private static func detailLine(model: MacShellModel, state: MacTunnelState) -> String? {
            switch state {
            case .inactive: nil
            case .active:
                // A session first seen already running has no observed start: the line stays and says so (SPEC 2.5).
                MacStrings.connectedForDuration(
                    model.traffic.startedAt.map { connectedDuration($0, now: model.now) } ?? MacStrings.unavailable,
                )
            case .activating, .reconnecting: MacStrings.menuWaiting
            case .blocked: MacStrings.trafficBlockedDetail
            case .signInWindow: MacStrings.menuSignInOpen
            case .notProtected, .unknown, .other: model.presentation.secondary
            }
        }

        private static func extra(model: MacShellModel, state: MacTunnelState) -> Extra? {
            switch state {
            case .blocked where model.showsCaptiveButton:
                .signIn(note: MacStrings.signInOffer(minutes(model.preferences.global.captiveWindowSeconds)))
            case .signInWindow: .signInOpen
            case .unknown: .serviceNotAnswering
            default: nil
            }
        }

        /// The command in flight concerns this page's tunnel.
        private static func isPending(_ model: MacShellModel, for profile: TunnelProfile) -> Bool {
            switch model.pendingAction {
            case let .connecting(id), let .arming(id), let .disarming(id): id == profile.id
            case .disconnecting: model.activeProfileID == profile.id
            case nil: false
            }
        }

        private static func minutes(_ seconds: Int) -> String {
            let minutes = max(1, seconds / 60)
            return minutes == 1 ? MacStrings.text1Minute : MacStrings.minutes(String(minutes))
        }

        /// "45 s", "12 min", "3 h 12 min", "2 d 4 h".
        package static func connectedDuration(_ start: Date, now: Date) -> String {
            TunnelPageRows.connectedDuration(start, now: now)
        }

        /// "18 seconds ago", "1 minute ago", "2 hours ago".
        package static func longAgo(_ date: Date, now: Date) -> String {
            TunnelPageRows.longAgo(date, now: now)
        }

        // MARK: Groups

        private static func traffic(model: MacShellModel, sample: TunnelStatistics?) -> Group {
            let rates = model.liveRates(sample)
            return Group(id: "traffic", title: MacStrings.trafficGroup, rows: [
                Row("download", MacStrings.download, transfer(rates?.download, MacLiveTunnelValues.total(sample, received: true))),
                Row("upload", MacStrings.upload, transfer(rates?.upload, MacLiveTunnelValues.total(sample, received: false))),
                TunnelPageRows.handshakeRow(sample, now: model.now),
            ])
        }

        private static func transfer(_ rate: Double?, _ total: UInt64?) -> String {
            guard rate != nil || total != nil else { return MacStrings.unavailable }
            return MacStrings.rateAndTotal(
                rate.map(UIFormat.rate) ?? MacStrings.unavailable,
                total.map(UIFormat.bytes) ?? MacStrings.unavailable,
            )
        }

        /// "b5XqT0…F2s=": keys are shortened on screen and copied in full (SPEC 5.2).
        package static func shortKey(_ text: String) -> String {
            TunnelPageRows.shortKey(text)
        }

        /// The rule's network types and list, or "Off" when the tunnel has none.
        package static func onDemandSummary(_ policy: OnDemandPolicy) -> String {
            let form = MacOnDemandForm(policy: policy)
            guard form.isEnabled else { return MacStrings.off }
            let base = switch (form.ethernet, form.wifi) {
            case (true, true): MacStrings.onDemandEthernetAndWiFi
            case (true, false): MacStrings.onDemandEthernet
            default: MacStrings.onDemandWiFi
            }
            guard form.wifi, !form.networks.isEmpty else { return base }
            return switch form.match {
            case .any: base
            case .only: MacStrings.onDemandOnlyNetworks(base, form.networks.count)
            case .except: MacStrings.onDemandExceptNetworks(base, form.networks.count)
            }
        }
    }

    /// Exclusions on the tunnel page (DEC-087, M08-T03); the row itself is shared in `TunnelPageRows`.
    extension MacTunnelPagePresentation {
        /// The warning line while the tunnel is up and some excluded host names could not be looked up.
        private static func unresolvedNote(_ names: [String]) -> String? {
            names.isEmpty ? nil : MacStrings.exclusionsUnresolved(names)
        }
    }

    public extension MacStartupOption {
        /// The tunnel page's words for the start-up choice (SPEC 8.1).
        var pageWord: String {
            switch self {
            case .off: MacStrings.startupNever
            case .login: MacStrings.startupAtLogin
            case .boot: MacStrings.startupAtStartUp
            }
        }
    }

    public extension MacShellModel {
        /// The kill switch as a state word (SPEC 5.2; the Mac has no kill switch setting). With a tunnel it is Off while
        /// another tunnel is the active one; without one it reads the app-wide state (the Protection page, M07-T05).
        func killSwitchWord(for profile: TunnelProfile?) -> String {
            if tunnelState == .unknown {
                return MacStrings.unavailable
            }
            if let profile, let activeProfileID, activeProfileID != profile.id {
                return MacStrings.off
            }
            return switch status.protection {
            case .protected: MacStrings.killSwitchOn
            case .blocked: MacStrings.killSwitchBlocking
            case .captiveWindow: MacStrings.killSwitchPaused
            case .unprotected: MacStrings.off
            case .unsupported, .unknown: MacStrings.unavailable
            }
        }
    }
#endif
