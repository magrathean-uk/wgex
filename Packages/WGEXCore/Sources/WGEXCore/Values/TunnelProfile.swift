// SPDX-License-Identifier: MIT
import Foundation

/// A versioned public profile; secret material is stored separately.
public struct TunnelProfile: Codable, Sendable, Identifiable, Hashable {
    /// Schema version written by this build.
    public static let currentSchemaVersion = 1

    /// Stable identifier.
    public let id: UUID
    /// Schema version of the stored document.
    public var schemaVersion: Int // 1
    /// Display name (1...128 characters).
    public var name: String // 1...128 chars, no control chars
    public var interface: InterfaceConfiguration
    public var peers: [PeerConfiguration] // 1...1024, unique public keys
    public var secrets: SecretReferences // where the private key, PSKs and carrier credentials live
    public var transport: TransportPolicy // candidates; `.udp` only until phase 6
    public var protection: ProtectionPolicy // per-profile protection options (global Mac settings live elsewhere)
    public var onDemand: OnDemandPolicy // iOS/tvOS
    public var macOptions: MacProfileOptions // startBeforeLogin, autoConnectAtLogin
    /// Destinations that leave outside the tunnel (DEC-087); absent in older documents, which decode as empty.
    public var exclusions: TunnelExclusions
    public var original: OriginalText? // retained import text with secret placeholders

    /// Creation time.
    public var createdAt: Date
    /// Last modification time.
    public var updatedAt: Date

    /// Creates a profile skeleton.
    public init(id: UUID = UUID(), name: String, createdAt: Date = Date(), updatedAt: Date? = nil) {
        self.id = id
        schemaVersion = Self.currentSchemaVersion
        self.name = name
        interface = InterfaceConfiguration(addresses: [], publicKey: .placeholder)
        peers = []
        secrets = SecretReferences(privateKey: .daemonStore(id: id))
        transport = .udp(id: TransportID(rawValue: id))
        protection = ProtectionPolicy(ipv6Policy: .tunnel)
        onDemand = .defaults(for: .current)
        macOptions = MacProfileOptions()
        exclusions = .empty
        original = nil
        self.createdAt = createdAt
        self.updatedAt = updatedAt ?? createdAt
    }

    /// Creates a complete profile. Mutable documents are checked with `validate()` before installation.
    public init(
        id: UUID = UUID(), name: String, interface: InterfaceConfiguration, peers: [PeerConfiguration],
        secrets: SecretReferences, transport: TransportPolicy = .udp(),
        protection: ProtectionPolicy, onDemand: OnDemandPolicy = .defaults(for: .current),
        macOptions: MacProfileOptions = MacProfileOptions(), exclusions: TunnelExclusions = .empty, original: OriginalText? = nil,
        createdAt: Date = Date(), updatedAt: Date? = nil,
    ) {
        self.id = id; schemaVersion = Self.currentSchemaVersion; self.name = name
        self.interface = interface; self.peers = peers; self.secrets = secrets; self.transport = transport
        self.protection = protection; self.onDemand = onDemand; self.macOptions = macOptions; self.exclusions = exclusions
        self.original = original
        self.createdAt = createdAt; self.updatedAt = updatedAt ?? createdAt
    }

    /// The profile an import saves (Mac import and replace, M05-T05): a fresh document under `id` that carries every tunnel
    /// setting of this one, exclusions included (DEC-087; M08-T09: the Mac import dropped them, so the daemon never carved
    /// their routes or passed them in the packet filter), the given startup options, new timestamps and no retained original.
    public func importedCopy(id: UUID, macOptions: MacProfileOptions) -> TunnelProfile {
        TunnelProfile(
            id: id, name: name, interface: interface, peers: peers, secrets: secrets, transport: transport,
            protection: protection, onDemand: onDemand, macOptions: macOptions, exclusions: exclusions,
        )
    }

    /// Reads the phase-0 identity-only documents as incomplete profiles, preserving the old wire API.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let id = try c.decode(UUID.self, forKey: .id)
        try self.init(
            id: id,
            name: c.decode(String.self, forKey: .name),
            createdAt: c.decode(Date.self, forKey: .createdAt),
            updatedAt: c.decode(Date.self, forKey: .updatedAt),
        )
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        interface = try c.decodeIfPresent(InterfaceConfiguration.self, forKey: .interface) ?? interface
        peers = try c.decodeIfPresent([PeerConfiguration].self, forKey: .peers) ?? peers
        secrets = try c.decodeIfPresent(SecretReferences.self, forKey: .secrets) ?? secrets
        transport = try c.decodeIfPresent(TransportPolicy.self, forKey: .transport) ?? transport
        protection = try c.decodeIfPresent(ProtectionPolicy.self, forKey: .protection) ?? protection
        onDemand = try c.decodeIfPresent(OnDemandPolicy.self, forKey: .onDemand) ?? onDemand
        macOptions = try c.decodeIfPresent(MacProfileOptions.self, forKey: .macOptions) ?? macOptions
        exclusions = try c.decodeIfPresent(TunnelExclusions.self, forKey: .exclusions) ?? .empty
        original = try c.decodeIfPresent(OriginalText.self, forKey: .original)
    }
}
