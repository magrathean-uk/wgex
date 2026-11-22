// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private enum ProfileFixture {
    static func make() throws -> TunnelProfile {
        try TunnelProfile(
            name: "Test tunnel",
            interface: InterfaceConfiguration(
                addresses: [IPAddressRange("192.0.2.7/24")],
                mtu: 1420,
                dns: [DNSServer("192.0.2.53")],
                publicKey: key(1),
            ),
            peers: [PeerConfiguration(publicKey: key(2), allowedIPs: [IPAddressRange("192.0.2.0/24")])],
            secrets: SecretReferences(privateKey: .keychain(persistentRef: Data([1, 2, 3]))),
            protection: ProtectionPolicy(ipv6Policy: .blockOutside),
            createdAt: Date(timeIntervalSince1970: 100),
        )
    }

    static func key(_ byte: UInt8) throws -> PublicKey {
        try PublicKey(rawValue: Data(repeating: byte, count: 32))
    }
}

private struct ProfileTests {
    @Test
    func `complete profiles with multiple secret references have stable sorted JSON`() throws {
        var profile = try ProfileFixture.make()
        let second = try ProfileFixture.key(3)
        try profile.peers.append(PeerConfiguration(publicKey: second, hasPresharedKey: true, allowedIPs: [IPAddressRange("2001:db8::/64")]))
        profile.peers[0].hasPresharedKey = true
        profile.secrets.presharedKeys[profile.peers[0].publicKey] = .daemonStore(id: UUID())
        profile.secrets.presharedKeys[second] = .keychain(persistentRef: Data([4, 5, 6]))
        profile.secrets.carrierCredentials[TransportID()] = .daemonStore(id: UUID())
        profile.secrets.carrierCredentials[TransportID()] = .daemonStore(id: UUID())
        profile.original = OriginalText(text: "PrivateKey = $WGEX_SECRET:fixture$", sha256OfOriginal: Data(count: 32))
        profile.onDemand = .wifiOnly(exceptSSIDs: ["Trusted"])
        profile.macOptions = MacProfileOptions(startBeforeLogin: true, autoConnectAtLogin: true)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(profile)
        let decoded = try JSONDecoder().decode(TunnelProfile.self, from: encoded)
        #expect(decoded == profile)
        #expect(try encoder.encode(decoded) == encoded)
        #expect(decoded.peers[0].id == decoded.peers[0].publicKey)
    }

    @Test
    func `legacy identity constructor and documents remain usable but incomplete`() throws {
        let profile = TunnelProfile(name: "Legacy")
        #expect(Set(profile.validate().map(\.code)).isSuperset(of: [.noPeers, .noAddresses]))
        let full = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile))
        var old = try #require(full as? [String: Any])
        for field in ["interface", "peers", "secrets", "transport", "protection", "onDemand", "macOptions", "original"] {
            old.removeValue(forKey: field)
        }
        let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONSerialization.data(withJSONObject: old))
        #expect(decoded.id == profile.id)
        #expect(decoded.name == profile.name)
        #expect(Set(decoded.validate().map(\.code)).isSuperset(of: [.noPeers, .noAddresses]))
    }

    @Test
    func `valid split profile produces no diagnostics`() throws {
        #expect(try ProfileFixture.make().validate().isEmpty)
    }

    @Test(arguments: [
        ConfigDiagnostic.Code.noAddresses,
        .noPeers,
        .duplicatePeer,
        .dnsOutsideAllowedIPs,
        .ipv6PolicyRequired,
        .carrierRequiresSinglePeer,
        .keepaliveClampedByCarrier,
        .keyInUseElsewhere,
        .invalidKey,
        .invalidPort,
        .invalidEndpoint,
        .controlCharacter,
        .invalidMTU,
    ])
    func `each cross-field invariant has its named diagnostic`(code: ConfigDiagnostic.Code) throws {
        var profile = try ProfileFixture.make()
        try Self.breakInvariant(code, in: &profile)
        let diagnostics = profile.validate(
            carrierActive: code == .carrierRequiresSinglePeer || code == .keepaliveClampedByCarrier,
            publicKeysInUse: code == .keyInUseElsewhere ? [profile.interface.publicKey] : [],
        )
        let diagnostic = try #require(diagnostics.first { $0.code == code })
        let warnings: Set<ConfigDiagnostic.Code> = [.dnsOutsideAllowedIPs, .keyInUseElsewhere, .keepaliveClampedByCarrier]
        #expect(diagnostic.severity == (warnings.contains(code) ? .warning : .error))
        #expect(diagnostic.line == nil)
        #expect(diagnostic.message == UserStrings.diagnostic(code))
    }

    @Test(arguments: [0, 1, 128, 129])
    func `name length counts characters`(count: Int) throws {
        var profile = try ProfileFixture.make(); profile.name = String(repeating: "é", count: count)
        #expect(profile.validate().contains { $0.code == .limitExceeded } == !(1 ... 128).contains(count))
    }

    @Test(arguments: ["\u{0}", "\n", "\r", "\t", "\u{7F}", "\u{85}"])
    func `name control characters are rejected`(character: String) throws {
        var profile = try ProfileFixture.make(); profile.name += character
        #expect(profile.validate().contains { $0.code == .controlCharacter })
    }

    @Test(arguments: [575, 576, 1279, 1280, 1500, 1501])
    func `MTU boundaries depend on IPv6 use`(mtu: UInt16) throws {
        var profile = try ProfileFixture.make(); profile.interface.mtu = mtu
        #expect(profile.validate().contains { $0.code == .invalidMTU } == !(1280 ... 1500).contains(mtu))
        try profile.interface.addresses.append(IPAddressRange("2001:db8::1/64"))
        #expect(profile.validate().contains { $0.code == .invalidMTU } == !(1280 ... 1500).contains(mtu))
    }

    @Test(arguments: [64, 65])
    func `DNS count cap is enforced`(count: Int) throws {
        var profile = try ProfileFixture.make(); profile.interface.dns = try Array(repeating: DNSServer("192.0.2.53"), count: count)
        #expect(profile.validate().contains { $0.code == .limitExceeded } == (count > 64))
    }

    @Test(arguments: [4096, 4097])
    func `AllowedIPs total cap is enforced`(count: Int) throws {
        var profile = try ProfileFixture.make(); profile.peers[0].allowedIPs = try Array(
            repeating: IPAddressRange("192.0.2.0/24"),
            count: count,
        )
        #expect(profile.validate().contains { $0.code == .limitExceeded } == (count > 4096))
    }

    @Test(arguments: [1024, 1025])
    func `peer count cap is enforced`(count: Int) throws {
        var profile = try ProfileFixture.make(); profile.peers = Array(repeating: profile.peers[0], count: count)
        #expect(profile.validate().contains { $0.code == .limitExceeded } == (count > 1024))
    }

    private static func breakInvariant(_ code: ConfigDiagnostic.Code, in profile: inout TunnelProfile) throws {
        // One mutation per invariant; transport/carrier context is supplied by the test.
        switch code {
        case .noAddresses: profile.interface.addresses = []
        case .noPeers: profile.peers = []
        case .duplicatePeer, .carrierRequiresSinglePeer: profile.peers.append(profile.peers[0])
        case .dnsOutsideAllowedIPs: profile.interface.dns = try [DNSServer("198.51.100.53")]
        case .ipv6PolicyRequired: profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/0")]; profile.protection.ipv6Policy = .tunnel
        case .keepaliveClampedByCarrier: profile.peers[0].persistentKeepalive = 26
        default: breakValueInvariant(code, in: &profile)
        }
    }

    private static func breakValueInvariant(_ code: ConfigDiagnostic.Code, in profile: inout TunnelProfile) {
        switch code {
        case .keyInUseElsewhere: break
        case .invalidKey: profile.peers[0].hasPresharedKey = true
        case .invalidPort: profile.peers[0].endpoint = Endpoint(host: "peer.test", port: 0)
        case .invalidEndpoint: profile.peers[0].endpoint = Endpoint(host: "bad host", port: 80)
        case .controlCharacter: profile.name = "Bad\nname"
        case .invalidMTU: profile.interface.mtu = 575
        default: Issue.record("Unhandled test mutation")
        }
    }
}

private struct PolicyTests {
    @Test
    func `platform flags and failover defaults are explicit`() {
        #expect(IOSProtection.defaults == IOSProtection(
            includeAllNetworks: false,
            excludeLocalNetworks: true,
            excludeCellularServices: true,
            excludeAPNs: true,
            excludeDeviceCommunication: true,
        ))
        #expect(TVProtection.defaults == TVProtection(enforceRoutes: true, allowLAN: true))
        #expect(MacGlobalSettings.defaults == MacGlobalSettings(
            lockdown: false,
            allowLAN: true,
            captiveWindowSeconds: 300,
            notifications: true,
        ))
        let defaults = FailoverPolicy.defaults()
        #expect(defaults.unhealthyWindows == 2); #expect(defaults.recoveryWindow == .seconds(30))
        #expect(defaults.failedEpisodeBackoff == .seconds(600)); #expect(!defaults.automaticFailback)
        #expect(!FeatureFlags.defaults.relayTransports)
        #expect(OnDemandPolicy.defaults(for: .macOS) == .off)
        #expect(OnDemandPolicy.defaults(for: .iOS) == .always(exceptSSIDs: []))
        #expect(OnDemandPolicy.defaults(for: .tvOS) == .always(exceptSSIDs: []))
    }

    @Test(arguments: [IPv6Policy.tunnel, .blockOutside, .allowOutside])
    func `v4 full tunnel requires a usable IPv6 choice including split defaults`(policy: IPv6Policy) throws {
        var profile = try ProfileFixture.make(); profile.protection.ipv6Policy = policy
        profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/1"), IPAddressRange("128.0.0.0/1")]
        #expect(profile.validate().contains { $0.code == .ipv6PolicyRequired } == (policy == .tunnel))
        try profile.interface.addresses.append(IPAddressRange("2001:db8::1/64"))
        #expect(!profile.validate().contains { $0.code == .ipv6PolicyRequired })
    }

    @Test
    func `blockOutside installs IPv6 routes and requires an IPv6-capable MTU`() throws {
        var profile = try ProfileFixture.make(); profile.interface.mtu = 1279
        profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/0")]
        #expect(profile.validate().contains { $0.code == .invalidMTU })
        profile.protection.ipv6Policy = .allowOutside
        #expect(profile.validate().contains { $0.code == .invalidMTU })
    }

    @Test
    func `system DNS warns about the consequence and split DNS rejects empty domains`() throws {
        var profile = try ProfileFixture.make(); profile.protection.dnsPolicy = .systemDefault
        #expect(profile.validate().contains { $0.severity == .warning && $0.message == UserStrings.systemDNSWarning })
        profile.protection.dnsPolicy = .split([])
        #expect(profile.validate().contains { $0.code == .invalidDNS })
        profile.protection.dnsPolicy = .split(["bad\ndomain"])
        #expect(profile.validate().contains { $0.code == .controlCharacter })
    }

    @Test
    func `manual override persists and missing candidates are rejected`() throws {
        var profile = try ProfileFixture.make()
        let candidate = try #require(profile.transport.candidates.first)
        profile.transport.selection = .manual(candidate.id)
        #expect(profile.validate().isEmpty)
        let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(profile))
        #expect(decoded.transport.selection == .manual(candidate.id))
        profile.transport.selection = .manual(TransportID())
        #expect(profile.validate().contains { $0.message == UserStrings.invalidTransport })
    }

    @Test
    func `automatic failback and invalid failover timing are rejected`() throws {
        var profile = try ProfileFixture.make()
        var policy = FailoverPolicy.defaults(order: profile.transport.candidates.map(\.id))
        policy.automaticFailback = true; profile.transport.selection = .automatic(policy)
        #expect(profile.validate().contains { $0.message == UserStrings.invalidTransport })
        policy.automaticFailback = false; policy.unhealthyWindows = 0; profile.transport.selection = .automatic(policy)
        #expect(profile.validate().contains { $0.message == UserStrings.invalidTransport })
        policy.unhealthyWindows = 2; policy.recoveryWindow = .zero; profile.transport.selection = .automatic(policy)
        #expect(profile.validate().contains { $0.message == UserStrings.invalidTransport })
    }

    @Test
    func `storage check omits only the missing address and peer`() throws {
        var profile = try ProfileFixture.make()
        #expect(profile.isComplete)
        #expect(profile.storageDiagnostics() == profile.validate())
        profile.interface.addresses = []
        profile.peers = []
        #expect(!profile.isComplete)
        #expect(Set(profile.validate().map(\.code)).isSuperset(of: [.noAddresses, .noPeers]))
        #expect(profile.storageDiagnostics() == profile.validate().filter { $0.code != .noAddresses && $0.code != .noPeers })
        #expect(!profile.storageDiagnostics().contains { $0.severity == .error })
        profile.name = ""
        #expect(profile.storageDiagnostics().contains { $0.code == .limitExceeded && $0.severity == .error })
        profile.name = "Blank"
        profile.peers = try [PeerConfiguration(publicKey: ProfileFixture.key(2), allowedIPs: [])]
        #expect(!profile.isComplete, "A server without an address is still incomplete")
    }

    @Test
    func `default limits and tighter limits cannot exceed resource bounds`() throws {
        let limits = ParseLimits.default
        #expect(limits.maximumBytes == 262_144); #expect(limits.maximumLines == 4096); #expect(limits.maximumPeers == 1024)
        #expect(limits.maximumAllowedIPs == 4096); #expect(limits.maximumDNS == 64); #expect(limits.maximumNameCharacters == 128)
        #expect(throws: ConfigurationError.invalidLimits) {
            try ParseLimits(
                maximumBytes: 262_145,
                maximumLines: 4096,
                maximumPeers: 1024,
                maximumAllowedIPs: 4096,
                maximumDNS: 64,
                maximumNameCharacters: 128,
            )
        }
        let tighter = try ParseLimits(
            maximumBytes: 1024,
            maximumLines: 32,
            maximumPeers: 2,
            maximumAllowedIPs: 4,
            maximumDNS: 1,
            maximumNameCharacters: 32,
        )
        #expect(tighter.maximumBytes == 1024)
    }
}
