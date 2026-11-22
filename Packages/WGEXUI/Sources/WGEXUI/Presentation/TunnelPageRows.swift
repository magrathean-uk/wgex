// SPDX-License-Identifier: MIT

// No platform guard: the Mac tunnel page and the iPhone and iPad tunnel page build the same rows (SPEC 5.2, 10).
import Foundation
import WGEXCore

/// Where a row with a disclosure leads.
public nonisolated enum TunnelPageLink: Equatable, Sendable {
    case routes, protectionPage, onDemand, startup, exclusions
}

/// One row of a tunnel page group.
public nonisolated struct TunnelPageRow: Equatable, Identifiable, Sendable {
    /// Stable key, also the accessibility item.
    public let id: String
    public let label: String
    /// What the row shows; keys are shortened.
    public let value: String
    /// What Copy puts on the pasteboard; always the full value.
    public let copyValue: String
    public var link: TunnelPageLink?
    public var monospaced = false

    package init(
        _ id: String, _ label: String, _ value: String, copy: String? = nil, link: TunnelPageLink? = nil, monospaced: Bool = false,
    ) {
        self.id = id; self.label = label; self.value = value; copyValue = copy ?? value
        self.link = link; self.monospaced = monospaced
    }
}

/// One titled group of a tunnel page.
public nonisolated struct TunnelPageGroup: Equatable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public let rows: [TunnelPageRow]
    /// A warning line under the rows: the excluded host names the running tunnel could not look up (DEC-087).
    public var note: String?

    package init(id: String, title: String, rows: [TunnelPageRow], note: String? = nil) {
        self.id = id; self.title = title; self.rows = rows; self.note = note
    }
}

/// Saved and live rows shared by every tunnel page. Saved rows always show; a missing live value says "Unavailable".
package nonisolated enum TunnelPageRows {
    /// "45 s", "12 min", "3 h 12 min", "2 d 4 h".
    package static func connectedDuration(_ start: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(start)))
        switch seconds {
        case ..<60: return MacStrings.s(String(seconds))
        case ..<3600: return MacStrings.min(String(seconds / 60))
        case ..<86400: return MacStrings.hoursAndMinutes(String(seconds / 3600), String(seconds % 3600 / 60))
        default: return MacStrings.daysAndHours(String(seconds / 86400), String(seconds % 86400 / 3600))
        }
    }

    /// "18 seconds ago", "1 minute ago", "2 hours ago".
    package static func longAgo(_ date: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(date)))
        let text = switch seconds {
        case ..<60: seconds == 1 ? MacStrings.text1Second : MacStrings.seconds(String(seconds))
        case ..<3600: seconds / 60 == 1 ? MacStrings.text1Minute : MacStrings.minutes(String(seconds / 60))
        case ..<86400: MacStrings.hours(seconds / 3600)
        default: MacStrings.days(seconds / 86400)
        }
        return text + MacStrings.ago
    }

    package static func handshakeRow(_ sample: TunnelStatistics?, now: Date) -> TunnelPageRow {
        TunnelPageRow(
            "lastHandshake",
            MacStrings.lastHandshake,
            MacLiveTunnelValues.handshake(sample).map { longAgo($0, now: now) } ?? MacStrings.unavailable,
        )
    }

    package static func uniqueRoutes(_ profile: TunnelProfile) -> [String] {
        var seen = Set<String>()
        return profile.peers.flatMap(\.allowedIPs).map(\.stringRepresentation).filter { seen.insert($0).inserted }
    }

    package static func addresses(_ profile: TunnelProfile, routes: [String]) -> [TunnelPageRow] {
        var rows: [TunnelPageRow] = []
        let addresses = profile.interface.addresses
        let v4 = addresses.filter { !$0.isIPv6 }.map(\.address)
        let v6 = addresses.filter(\.isIPv6).map(\.address)
        if !v4.isEmpty {
            rows.append(TunnelPageRow("tunnelAddress", MacStrings.tunnelAddress, v4.joined(separator: ", ")))
        }
        if !v6.isEmpty {
            rows.append(TunnelPageRow("ipv6Address", MacStrings.ipv6Address, v6.joined(separator: ", ")))
        }
        if !profile.interface.dns.isEmpty {
            rows.append(TunnelPageRow("dns", MacStrings.dns, profile.interface.dns.map(\.stringRepresentation).joined(separator: ", ")))
        }
        if !routes.isEmpty {
            let fullRoute = profile.peers.flatMap(\.allowedIPs).contains { !$0.isIPv6 && $0.networkPrefixLength == 0 }
            let summary = fullRoute ? MacStrings.allTraffic : MacStrings.routeCount(routes.count)
            rows.append(TunnelPageRow("routes", MacStrings.routes, summary, copy: routes.joined(separator: ", "), link: .routes))
        }
        return rows
    }

    package static func server(_ peer: PeerConfiguration, index: Int, up: Bool, sample: TunnelStatistics?) -> [TunnelPageRow] {
        var rows: [TunnelPageRow] = []
        if let endpoint = peer.endpoint {
            rows.append(TunnelPageRow("peer.\(index).name", MacStrings.name, endpoint.host))
        }
        if up {
            let inUse = MacLiveTunnelValues.endpointInUse(peer, sample: sample) ?? MacStrings.unavailable
            rows.append(TunnelPageRow("peer.\(index).address", MacStrings.address, inUse))
        }
        rows.append(keyRow("peer.\(index).publicKey", MacStrings.publicKey, peer.publicKey))
        if let keepalive = peer.persistentKeepalive, keepalive > 0 {
            rows.append(TunnelPageRow("peer.\(index).keepalive", MacStrings.keepalive, MacStrings.keepaliveEvery(Int(keepalive))))
        }
        return rows
    }

    /// "None", or the count leading to the list of exclusions (DEC-087, M08-T03).
    package static func exclusionsRow(_ entries: [String]) -> TunnelPageRow {
        guard !entries.isEmpty else { return TunnelPageRow("exclusions", MacStrings.exclusions, MacStrings.exclusionsNone) }
        return TunnelPageRow(
            "exclusions", MacStrings.exclusions, MacStrings.exclusionCount(entries.count),
            copy: entries.joined(separator: ", "), link: .exclusions,
        )
    }

    package static func keyRow(_ id: String, _ label: String, _ key: PublicKey) -> TunnelPageRow {
        TunnelPageRow(id, label, shortKey(key.base64), copy: key.base64, monospaced: true)
    }

    /// "b5XqT0…F2s=": keys are shortened on screen and copied in full (SPEC 5.2).
    package static func shortKey(_ text: String) -> String {
        text.count > 12 ? "\(text.prefix(6))…\(text.suffix(4))" : text
    }
}
