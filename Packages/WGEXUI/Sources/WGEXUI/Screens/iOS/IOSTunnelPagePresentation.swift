// SPDX-License-Identifier: MIT

// No iOS guard: host unit tests read the iPhone and iPad tunnel page without a view. Main-actor isolated, as the
// on-demand form it summarises is.
import Foundation
import WGEXCore

/// The iPhone and iPad tunnel page as plain rows (SPEC 5.2 carried to iOS by SPEC 10): the status word with its switch,
/// then the Mac's Traffic, Addresses, Server, Protection (with Exclusions, DEC-087) and Advanced groups. Saved rows always
/// show; live rows show only while this tunnel is up, and a missing live value says "Unavailable". iOS measures totals, not
/// rates.
public struct IOSTunnelPagePresentation: Equatable, Sendable {
    /// Which device's words the page uses.
    public enum Device: Sendable {
        case iPhone, iPad
    }

    public struct Status: Equatable, Sendable {
        public let state: MacTunnelState
        /// The SPEC 3 status word beside the switch.
        public let word: String
        /// The second line; nil when the app has nothing true to say (Inactive, and Active without a recorded start).
        public let detail: String?
    }

    public let title: String
    public let status: Status
    /// Groups after the status group, in SPEC 5.2 order.
    public let groups: [TunnelPageGroup]
    /// Every route over all servers, for the Routes page.
    public let routes: [String]
    /// Every exclusion in the core's spelling, for the Exclusions page.
    public let exclusions: [String]

    /// `statistics` is this tunnel's own live sample, or nil; the caller never passes another tunnel's counters.
    public init(
        profile: TunnelProfile,
        status: TunnelStatus,
        activeProfileID: UUID?,
        userInitiated: Bool,
        statistics: TunnelStatistics?,
        protection: ProtectionPolicy,
        device: Device,
        now: Date = Date(),
    ) {
        title = profile.name
        let isActive = activeProfileID == profile.id
        let presentation = IOSStatusPresentation(status: isActive ? status : .idle, userInitiated: userInitiated, now: now)
        let state = isActive ? MacTunnelState(presentation: presentation.protection, status: status) : .inactive
        self.status = Status(state: state, word: state.word(now: now), detail: Self.detail(state, presentation: presentation.protection))
        let up = isActive && state.isUp
        let sample = up || (isActive && state == .blocked) ? statistics : nil
        routes = TunnelPageRows.uniqueRoutes(profile)
        exclusions = profile.exclusions.entries.map(\.text)
        var groups: [TunnelPageGroup] = []
        if up {
            groups.append(TunnelPageGroup(id: "traffic", title: MacStrings.trafficGroup, rows: [
                TunnelPageRow("download", MacStrings.download, Self.total(sample, received: true)),
                TunnelPageRow("upload", MacStrings.upload, Self.total(sample, received: false)),
                TunnelPageRows.handshakeRow(sample, now: now),
            ]))
        } else if isActive, state == .blocked {
            groups.append(TunnelPageGroup(id: "traffic", title: MacStrings.trafficGroup, rows: [
                TunnelPageRows.handshakeRow(sample, now: now),
                TunnelPageRow("transfer", MacStrings.downloadAndUpload, MacStrings.unavailable),
            ]))
        }
        let addresses = TunnelPageRows.addresses(profile, routes: routes)
        if !addresses.isEmpty {
            groups.append(TunnelPageGroup(id: "addresses", title: MacStrings.addresses, rows: addresses))
        }
        for (index, peer) in profile.peers.enumerated() {
            let title = profile.peers.count == 1 ? MacStrings.serverGroup : MacStrings.serverNumber(index + 1)
            let rows = TunnelPageRows.server(peer, index: index, up: up, sample: sample)
            groups.append(TunnelPageGroup(id: "server.\(index)", title: title, rows: rows))
        }
        let notes = up ? Self.exclusionNotes(status) : []
        groups.append(Self.protectionGroup(profile, exclusions: exclusions, protection: protection, notes: notes))
        groups.append(Self.advancedGroup(profile, up: up, sample: sample, device: device))
        self.groups = groups
    }

    private static func protectionGroup(
        _ profile: TunnelProfile, exclusions: [String], protection: ProtectionPolicy, notes: [String],
    ) -> TunnelPageGroup {
        TunnelPageGroup(id: "protection", title: MacStrings.protection, rows: [
            TunnelPageRow(
                "forceAllTraffic", PlatformStrings.forceAllTraffic,
                protection.ios.includeAllNetworks ? MacStrings.killSwitchOn : MacStrings.off, link: .protectionPage,
            ),
            TunnelPageRow(
                "localNetwork", MacStrings.localNetwork,
                protection.ios.excludeLocalNetworks ? MacStrings.localNetworkAllowed : MacStrings.localNetworkNotAllowed,
                link: .protectionPage,
            ),
            TunnelPageRows.exclusionsRow(exclusions),
            TunnelPageRow(
                "onDemand", MacStrings.connectOnDemand, IOSOnDemandForm(policy: profile.onDemand).activationSummary, link: .onDemand,
            ),
        ], note: notes.isEmpty ? nil : notes.joined(separator: "\n"))
    }

    /// Warning lines under the Exclusions row while the tunnel is up: exclusions not applied under Force all traffic,
    /// port exclusions this device ignores, and host names that did not resolve (DEC-127).
    private static func exclusionNotes(_ status: TunnelStatus) -> [String] {
        var notes: [String] = []
        if !status.forceAllIgnoredExclusions.isEmpty {
            notes.append(UserStrings.exclusionsForceAllTraffic)
        }
        if !status.unsupportedExclusionPorts.isEmpty {
            notes.append(UserStrings.exclusionPortsUnsupported(status.unsupportedExclusionPorts))
        }
        if !status.unresolvedExclusions.isEmpty {
            notes.append(UserStrings.exclusionUnresolved(status.unresolvedExclusions))
        }
        return notes
    }

    private static func advancedGroup(_ profile: TunnelProfile, up: Bool, sample: TunnelStatistics?, device: Device) -> TunnelPageGroup {
        var rows: [TunnelPageRow] = []
        if up {
            rows.append(TunnelPageRow("interface", MacStrings.interface, sample?.interfaceName ?? MacStrings.unavailable))
        }
        rows.append(TunnelPageRow("mtu", MacStrings.mtu, profile.interface.mtu.map(String.init) ?? MacStrings.automatic))
        let keyLabel = device == .iPad ? PlatformStrings.thisIPadsPublicKey : PlatformStrings.thisIPhonesPublicKey
        rows.append(TunnelPageRows.keyRow("publicKey", keyLabel, profile.interface.publicKey))
        return TunnelPageGroup(id: "advanced", title: MacStrings.advancedGroup, rows: rows)
    }

    private static func detail(_ state: MacTunnelState, presentation: ProtectionPresentation) -> String? {
        switch state {
        // iOS records no session start, so "Connected for" is left out rather than shown as Unavailable (SPEC 2.5, E5).
        case .inactive, .active: nil
        case .activating, .reconnecting: MacStrings.menuWaiting
        case .blocked, .signInWindow, .notProtected, .unknown, .other: presentation.secondary.isEmpty ? nil : presentation.secondary
        }
    }

    /// Bytes across every peer of the sample, never an invented zero.
    private static func total(_ sample: TunnelStatistics?, received: Bool) -> String {
        MacLiveTunnelValues.total(sample, received: received).map(UIFormat.bytes) ?? MacStrings.unavailable
    }

    /// The short word after a tunnel's name on the first screen; nil while inactive (SPEC 5.1).
    public static func listWord(profileID: UUID, status: TunnelStatus, activeProfileID: UUID?, userInitiated: Bool) -> String? {
        guard activeProfileID == profileID else { return nil }
        let presentation = IOSStatusPresentation(status: status, userInitiated: userInitiated)
        return MacTunnelState(presentation: presentation.protection, status: status).sidebarWord
    }
}
