// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Stable peer identity survives public key edits and reorder operations.
public struct PeerEditorDraft: Identifiable, Hashable {
    public let id: UUID
    public var publicKey: String
    public var endpoint: String
    public var allowedIPs: AllowedIPsModel
    public var keepalive: String
    package var presharedReference: SecretRef?

    public init(id: UUID = UUID()) {
        self.id = id; publicKey = ""; endpoint = ""; allowedIPs = AllowedIPsModel(); keepalive = ""
    }

    package init(peer: PeerConfiguration, reference: SecretRef?) {
        id = UUID(); publicKey = peer.publicKey.base64; endpoint = peer.endpoint?.stringRepresentation ?? ""
        allowedIPs = AllowedIPsModel(peer.allowedIPs.map(\.stringRepresentation))
        keepalive = peer.persistentKeepalive.map(String.init) ?? ""; presharedReference = reference
    }
}

/// Public draft text only. Secret buffers belong to the editor model.
public struct ProfileEditorDraft: Hashable {
    public var name: String
    public var addresses: String
    public var listenPort: String
    public var mtu: String
    /// A change reconciles the DNS host routes of every peer with an "Exclude private networks"
    /// control (DEC-020): departed servers lose their host routes whether it is on or off, and only
    /// while on are the current servers' routes added, so a private resolver stays routed however
    /// the field is edited and no stale route survives an off, edit, on sequence.
    public var dns: String {
        didSet { syncDNSHostRoutes(from: oldValue) }
    }

    public var searchDomains: String
    public var peers: [PeerEditorDraft]
    public var protection: ProtectionPolicy
    /// The stored policy; the macOS editor edits ``onDemandForm`` and ``resolvedOnDemand`` joins them.
    public var onDemand: OnDemandPolicy
    /// The macOS on-demand editor state (ADR-030).
    public var onDemandForm: MacOnDemandForm
    public var macOptions: MacProfileOptions
    /// Exclusions (DEC-087) as entry texts, one per line, in the core's canonical spelling.
    public var exclusions: [String]

    package init(_ profile: TunnelProfile) {
        name = profile.name; addresses = profile.interface.addresses.map(\.stringRepresentation).joined(separator: ", ")
        listenPort = profile.interface.listenPort.map(String.init) ?? ""; mtu = profile.interface.mtu.map(String.init) ?? ""
        dns = profile.interface.dns.map(\.stringRepresentation).joined(separator: ", ")
        searchDomains = profile.interface.searchDomains.joined(separator: ", ")
        peers = profile.peers.map { PeerEditorDraft(peer: $0, reference: profile.secrets.presharedKeys[$0.publicKey]) }
        protection = profile.protection; onDemand = profile.onDemand; macOptions = profile.macOptions
        onDemandForm = MacOnDemandForm(policy: profile.onDemand)
        exclusions = profile.exclusions.entries.map(\.text)
    }

    private mutating func syncDNSHostRoutes(from old: String) {
        guard dns != old else { return }
        let oldServers = ProfileEditorModel.parts(old), newServers = ProfileEditorModel.parts(dns)
        for index in peers.indices {
            peers[index].allowedIPs.reconcileDNSHostRoutes(from: oldServers, to: newServers)
        }
    }

    /// The policy to save: the stored one while the form is unchanged, otherwise what the form writes.
    public var resolvedOnDemand: OnDemandPolicy {
        onDemandForm.resolved(against: onDemand)
    }
}

/// A diagnostic target; peer fields carry stable draft identities.
public nonisolated enum EditorField: Hashable, Sendable {
    case summary, name, privateKey, addresses, listenPort, mtu, dns, searchDomains, peers, ipv6Policy, dnsPolicy, transport, onDemand
    case exclusions
    case publicKey(UUID), presharedKey(UUID), endpoint(UUID), allowedIPs(UUID), keepalive(UUID)
}

public nonisolated extension EditorField {
    /// Translation-independent item key for a field and, where applicable, its peer.
    var automationKey: String {
        switch self {
        case .summary: "summary"
        case .name: "name"
        case .privateKey: "privateKey"
        case .addresses: "addresses"
        case .listenPort: "listenPort"
        case .mtu: "mtu"
        case .dns: "dns"
        case .searchDomains: "searchDomains"
        case .peers: "peers"
        case .ipv6Policy: "ipv6Policy"
        case .dnsPolicy: "dnsPolicy"
        case .transport: "transport"
        case .onDemand: "onDemand"
        case .exclusions: "exclusions"
        case let .publicKey(id): "publicKey." + id.uuidString
        case let .presharedKey(id): "presharedKey." + id.uuidString
        case let .endpoint(id): "endpoint." + id.uuidString
        case let .allowedIPs(id): "allowedIPs." + id.uuidString
        case let .keepalive(id): "keepalive." + id.uuidString
        }
    }
}

public struct EditorDiagnostic: Hashable {
    public let diagnostic: ConfigDiagnostic
    public let fields: Set<EditorField>

    public init(_ diagnostic: ConfigDiagnostic, fields: Set<EditorField>) {
        self.diagnostic = diagnostic; self.fields = fields
    }
}
