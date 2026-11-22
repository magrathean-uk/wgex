// SPDX-License-Identifier: MIT

// No iOS guard: host unit tests compile this presentation mapping.
import Foundation
import WGEXCore

/// Public configuration only. No secret reference or secret bytes enter the view data.
public nonisolated struct IOSInfoField: Identifiable, Sendable, Hashable {
    public let id: String
    public let title: String
    public let value: String
    public var monospaced = false
}

/// iOS presentation values compiled on the host as well as the simulator.
/// Protection claims, chips and colours remain owned by the shared presenter.
public nonisolated struct IOSStatusPresentation: Sendable {
    public let protection: ProtectionPresentation
    public let handshake: StatValue
    // Rates are not sampled on iOS; health's default zero rates are not measurements.
    public let download: StatValue = .unavailable
    public let upload: StatValue = .unavailable
    /// Totals across every peer of the live sample; unavailable without one, never an invented zero.
    public let received: StatValue
    public let sent: StatValue
    private let now: Date
    private let peers: [PeerStatistics]?

    /// `statistics` is the active tunnel's live sample, passed only for the tunnel it belongs to.
    public init(
        status: TunnelStatus,
        userInitiated: Bool,
        now: Date = Date(),
        staleness: Staleness = .fresh,
        statistics: TunnelStatistics? = nil,
    ) {
        let context = ProtectionContext(
            platform: .iOS, now: now, staleness: staleness,
            userInitiated: userInitiated, unknownReason: .extensionUnavailable,
        )
        let presentation = ProtectionPresentation(status: status, context: context)
        protection = presentation
        self.now = now
        peers = statistics?.peers
        let latest = statistics?.peers.compactMap(\.lastHandshake).max() ?? status.health.lastHandshake
        if let latest {
            handshake = .age(since: latest, now: now)
        } else if statistics != nil {
            handshake = .text(Self.noHandshake)
        } else {
            handshake = .unavailable
        }
        received = statistics.map { .bytes(Self.total($0.peers.map(\.rxBytes))) } ?? .unavailable
        sent = statistics.map { .bytes(Self.total($0.peers.map(\.txBytes))) } ?? .unavailable
    }

    public static let noHandshake = "No handshake yet"

    public func peerHandshakeText(peerCount: Int) -> String {
        peerCount == 1 ? handshake.text : "Not sampled per peer"
    }

    /// Latest handshake, data received and data sent for one peer, from the live sample when it lists that peer.
    public func peerCounters(_ publicKey: PublicKey, peerCount: Int) -> [IOSInfoField] {
        let key = publicKey.base64
        guard let sample = peers?.first(where: { $0.publicKey == publicKey }) else {
            return [
                IOSInfoField(id: key + ".handshake", title: "Latest handshake", value: peerHandshakeText(peerCount: peerCount)),
                IOSInfoField(id: key + ".received", title: "Data received", value: StatValue.unavailable.text),
                IOSInfoField(id: key + ".sent", title: "Data sent", value: StatValue.unavailable.text),
            ]
        }
        let handshake = sample.lastHandshake.map { UIFormat.ago($0, now: now) } ?? Self.noHandshake
        return [
            IOSInfoField(id: key + ".handshake", title: "Latest handshake", value: handshake),
            IOSInfoField(id: key + ".received", title: "Data received", value: UIFormat.bytes(sample.rxBytes)),
            IOSInfoField(id: key + ".sent", title: "Data sent", value: UIFormat.bytes(sample.txBytes)),
        ]
    }

    /// Saturating sum, so a corrupt counter never traps.
    private static func total(_ values: [UInt64]) -> UInt64 {
        values.reduce(0) { sum, value in
            let (result, overflow) = sum.addingReportingOverflow(value)
            return overflow ? .max : result
        }
    }

    public static func details(_ profile: TunnelProfile) -> [IOSInfoField] {
        var fields = [
            IOSInfoField(id: "addresses", title: "Addresses", value: available(profile.interface.addresses.map(\.stringRepresentation))),
            IOSInfoField(
                id: "dns",
                title: "DNS",
                value: available(profile.interface.dns.map(\.stringRepresentation), fallback: "Not configured"),
            ),
            IOSInfoField(id: "mtu", title: "MTU", value: profile.interface.mtu.map(String.init) ?? "Automatic"),
            IOSInfoField(id: "publicKey", title: "Public key", value: profile.interface.publicKey.base64, monospaced: true),
        ]
        for (index, peer) in profile.peers.enumerated() {
            let prefix = "peer.\(index)."
            let title = "Peer \(index + 1)"
            fields += [
                IOSInfoField(
                    id: prefix + "endpoint",
                    title: title + " endpoint",
                    value: peer.endpoint.map(EndpointText.format) ?? "No endpoint",
                ),
                IOSInfoField(
                    id: prefix + "allowedIPs",
                    title: title + " allowed IPs",
                    value: available(peer.allowedIPs.map(\.stringRepresentation)),
                ),
                IOSInfoField(
                    id: prefix + "keepalive",
                    title: title + " persistent keepalive",
                    value: peer.persistentKeepalive.map { "Every \($0) seconds" } ?? "Off",
                ),
                IOSInfoField(id: prefix + "publicKey", title: title + " public key", value: peer.publicKey.base64, monospaced: true),
            ]
        }
        return fields
    }

    /// Configured settings, separate from the measured state in the connection card.
    public static func protectionFields(policy: ProtectionPolicy, onDemand: OnDemandPolicy) -> [IOSInfoField] {
        let demand: String = switch onDemand {
        case .off: "Off"
        case let .always(names): names.isEmpty ? "Always" : "Always except trusted networks"
        case let .wifiOnly(names): names.isEmpty ? "Wi-Fi only" : "Wi-Fi only except trusted networks"
        case .cellularOnly: "Cellular only"
        case .interfaces: "Mac only"
        case let .iosInterfaces(interfaces): onDemandLabel(interfaces)
        }
        return [
            IOSInfoField(id: "force", title: "Force all traffic", value: policy.ios.includeAllNetworks ? "On" : "Off"),
            IOSInfoField(id: "lan", title: "Allow local network", value: policy.ios.excludeLocalNetworks ? "On" : "Off"),
            IOSInfoField(id: "onDemand", title: IOSOnDemandStrings.detailRow, value: demand),
        ]
    }

    private static func onDemandLabel(_ interfaces: OnDemandIOSInterfaces) -> String {
        let base: String
        switch interfaces {
        case .cellularOnly: return "Cellular only"
        case .wifiOnly: base = "Wi-Fi only"
        case .wifiOrCellular: base = "Wi-Fi or cellular"
        }
        return switch interfaces.ssidMatch ?? .anySSID {
        case .anySSID: base
        case .onlySSIDs: base + ", listed Wi-Fi networks only"
        case .exceptSSIDs: base + " except trusted networks"
        }
    }

    private static func available(_ values: [String], fallback: String = "None") -> String {
        values.isEmpty ? fallback : values.joined(separator: ", ")
    }
}
