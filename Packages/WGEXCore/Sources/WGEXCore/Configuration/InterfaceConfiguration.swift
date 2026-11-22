// SPDX-License-Identifier: MIT

public struct InterfaceConfiguration: Codable, Sendable, Hashable {
    public var addresses: [IPAddressRange] // ≥1
    public var listenPort: UInt16?
    /// 1280...1500 on Apple platforms: IPv6 minimum through the tunnel interface maximum.
    public var mtu: UInt16?
    public var dns: [DNSServer] // ≤64
    public var searchDomains: [String]
    /// Derived during import; display never requires unlocking secrets.
    public var publicKey: PublicKey // derived at import; display without unlocking secrets

    public init(
        addresses: [IPAddressRange], listenPort: UInt16? = nil, mtu: UInt16? = nil,
        dns: [DNSServer] = [], searchDomains: [String] = [], publicKey: PublicKey,
    ) {
        self.addresses = addresses; self.listenPort = listenPort; self.mtu = mtu
        self.dns = dns; self.searchDomains = searchDomains; self.publicKey = publicKey
    }
}

public struct PeerConfiguration: Codable, Sendable, Hashable, Identifiable {
    public var id: PublicKey {
        publicKey
    }

    public var publicKey: PublicKey
    public var hasPresharedKey: Bool
    public var allowedIPs: [IPAddressRange] // ≤4096
    public var endpoint: Endpoint? // host or literal + port
    public var persistentKeepalive: UInt16?

    public init(
        publicKey: PublicKey, hasPresharedKey: Bool = false, allowedIPs: [IPAddressRange],
        endpoint: Endpoint? = nil, persistentKeepalive: UInt16? = nil,
    ) {
        self.publicKey = publicKey; self.hasPresharedKey = hasPresharedKey; self.allowedIPs = allowedIPs
        self.endpoint = endpoint; self.persistentKeepalive = persistentKeepalive
    }
}
