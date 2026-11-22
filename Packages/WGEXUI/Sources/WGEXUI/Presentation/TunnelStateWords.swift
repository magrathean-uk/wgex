// SPDX-License-Identifier: MIT

// No platform guard: the Mac and the iPhone and iPad pages share these words and live values.
import Foundation
import WGEXCore

/// One status word for the menu, the sidebar and the tunnel page (SPEC 3), so the three never disagree.
public nonisolated enum MacTunnelState: Equatable, Sendable {
    case inactive, active, activating, reconnecting, blocked
    /// The sign-in window is open until `expires`.
    case signInWindow(expires: Date)
    case notProtected, unknown
    /// A state the Mac does not expect (unsupported); keeps the presentation's own text.
    case other(String)

    /// The app-wide state from the shared presentation (SPEC 3's mapping), the same on the Mac, iPhone and iPad.
    public init(presentation: ProtectionPresentation, status: TunnelStatus) {
        let verdict = presentation.verdict
        switch verdict {
        case .protected: self = .active; return
        case .inactive: self = .inactive; return
        case .connecting: self = .activating; return
        case .reasserting: self = .reconnecting; return
        case .blocked: self = .blocked; return
        case .unknown, .stale: self = .unknown; return
        case .captiveWindow, .unprotected, .unsupported: break
        }
        if case let .captiveWindow(expires) = status.protection {
            self = .signInWindow(expires: expires)
        } else if verdict == .unprotected {
            self = status.phase == .idle ? .inactive : .notProtected
        } else {
            self = .other(presentation.primary)
        }
    }

    /// The word the menu's Status line and the tunnel page use.
    public func word(now: Date) -> String {
        switch self {
        case .inactive: MacStrings.inactive
        case .active: MacStrings.active
        case .activating: MacStrings.menuActivating
        case .reconnecting: MacStrings.menuReconnecting
        case .blocked: MacStrings.menuTrafficBlocked
        case let .signInWindow(expires): MacStrings.menuUnprotected(expires.timeIntervalSince(now))
        case .notProtected: MacStrings.menuNotProtected
        case .unknown: MacStrings.menuUnknown
        case let .other(text): text
        }
    }

    /// The short grey word after a tunnel's name in the sidebar; nil when inactive (SPEC 5.1).
    public var sidebarWord: String? {
        switch self {
        case .inactive: nil
        case .active: MacStrings.active
        case .activating: MacStrings.menuActivating
        case .reconnecting: MacStrings.menuReconnecting
        case .blocked: MacStrings.sidebarBlocked
        case .signInWindow, .notProtected: MacStrings.unprotected
        case .unknown: MacStrings.menuUnknown
        case let .other(text): text
        }
    }

    /// The tunnel is up: live rows (traffic, server address, interface) belong on its page.
    public var isUp: Bool {
        switch self {
        case .active, .reconnecting, .signInWindow: true
        default: false
        }
    }
}

/// Live values read from one statistics sample, shared by the menu and the tunnel page.
package nonisolated enum MacLiveTunnelValues {
    /// The address a peer is talking to, as IP:port; nil when the sample has none or only a name.
    package static func endpointInUse(_ peer: PeerConfiguration, sample: TunnelStatistics?) -> String? {
        guard let endpoint = sample?.peers.first(where: { $0.publicKey == peer.publicKey })?.endpoint,
              (try? IPAddressRange(endpoint.host)) != nil else { return nil }
        return EndpointText.format(endpoint)
    }

    /// Every peer with an endpoint, measured or saved, by its address in use, "Unavailable" where unmeasured.
    package static func liveEndpoint(_ profile: TunnelProfile, sample: TunnelStatistics?) -> String {
        let peers = profile.peers.filter { peer in
            peer.endpoint != nil || sample?.peers.contains { $0.publicKey == peer.publicKey && $0.endpoint != nil } == true
        }
        guard !peers.isEmpty else { return MacStrings.unavailable }
        return peers.map { endpointInUse($0, sample: sample) ?? MacStrings.unavailable }.joined(separator: ", ")
    }

    /// Before the server answers the saved endpoint shows (SPEC 4.3); a measured address replaces it per peer.
    package static func pendingEndpoint(_ profile: TunnelProfile, sample: TunnelStatistics?) -> String {
        let endpoints = profile.peers.compactMap { peer in
            endpointInUse(peer, sample: sample) ?? peer.endpoint.map(EndpointText.format)
        }
        return endpoints.isEmpty ? MacStrings.unavailable : endpoints.joined(separator: ", ")
    }

    /// Bytes received or sent across all peers; nil without peers or on overflow.
    package static func total(_ sample: TunnelStatistics?, received: Bool) -> UInt64? {
        guard let sample, !sample.peers.isEmpty else { return nil }
        var total: UInt64 = 0
        for peer in sample.peers {
            let sum = total.addingReportingOverflow(received ? peer.rxBytes : peer.txBytes)
            guard !sum.overflow else { return nil }
            total = sum.partialValue
        }
        return total
    }

    /// The most recent handshake of any peer.
    package static func handshake(_ sample: TunnelStatistics?) -> Date? {
        sample?.peers.compactMap(\.lastHandshake).max()
    }
}
