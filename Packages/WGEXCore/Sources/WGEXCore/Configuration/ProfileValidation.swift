// SPDX-License-Identifier: MIT
import Foundation

public extension TunnelProfile {
    /// Pure cross-field checks. The transport owner supplies `carrierActive` after selecting a carrier.
    /// Public-key reuse is supplied by the profile registry.
    func validate(carrierActive: Bool = false, publicKeysInUse: Set<PublicKey> = []) -> [ConfigDiagnostic] {
        var validator = ProfileValidator(profile: self, carrierActive: carrierActive, publicKeysInUse: publicKeysInUse)
        return validator.run()
    }

    /// The checks a saved document must pass where a tunnel may still lack an address or a server (DEC-088): `validate()`
    /// without `noAddresses` and `noPeers`. Activation still needs `validate()` to pass.
    func storageDiagnostics(carrierActive: Bool = false, publicKeysInUse: Set<PublicKey> = []) -> [ConfigDiagnostic] {
        validate(carrierActive: carrierActive, publicKeysInUse: publicKeysInUse)
            .filter { $0.code != .noAddresses && $0.code != .noPeers }
    }

    /// Whether the tunnel has at least one address and one peer, the minimum it needs before it can be activated.
    var isComplete: Bool {
        !interface.addresses.isEmpty && !peers.isEmpty
    }
}

private struct ProfileValidator {
    let profile: TunnelProfile
    let carrierActive: Bool
    let publicKeysInUse: Set<PublicKey>
    private var diagnostics: [ConfigDiagnostic] = []
    private var routes: [IPAddressRange] {
        profile.peers.flatMap(\.allowedIPs)
    }

    private var fullIPv4: Bool {
        Self.coversIPv4Default(routes)
    }

    init(profile: TunnelProfile, carrierActive: Bool, publicKeysInUse: Set<PublicKey>) {
        self.profile = profile; self.carrierActive = carrierActive; self.publicKeysInUse = publicKeysInUse
    }

    mutating func run() -> [ConfigDiagnostic] {
        checkPublicFields(); checkLimits(); checkInterface(); checkPeers(); checkDNS(); checkTransport(); checkOnDemand(); checkExclusions()
        return diagnostics
    }

    private mutating func issue(_ code: ConfigDiagnostic.Code, _ severity: ConfigDiagnostic.Severity = .error, message: String? = nil) {
        diagnostics.append(ConfigDiagnostic(severity: severity, code: code, message: message))
    }

    private mutating func checkPublicFields() {
        var fields = [profile.name] + profile.interface.searchDomains + profile.interface.dns.map(\.stringRepresentation)
        fields += profile.peers.compactMap { $0.endpoint?.host }
        if case let .split(domains) = profile.protection.dnsPolicy {
            fields += domains
        }
        fields += profile.onDemand.namedSSIDs
        fields += profile.exclusions.hostNames
        if fields.contains(where: { PublicFieldSafety.containsKey($0.utf8) }) {
            issue(.invalidKey, message: UserStrings.secretInPublicField)
        }
    }

    private mutating func checkLimits() {
        if !(1 ... 128).contains(profile.name.count) {
            issue(.limitExceeded)
        }
        if Self.hasControl(profile.name) {
            issue(.controlCharacter)
        }
        if profile.schemaVersion != TunnelProfile.currentSchemaVersion {
            issue(.unknownKey, message: UserStrings.unsupportedSchema)
        }
        if profile.interface.addresses.isEmpty {
            issue(.noAddresses)
        }
        if profile.peers.isEmpty {
            issue(.noPeers)
        }
        if profile.peers.count > 1024 || profile.interface.dns.count + profile.interface.searchDomains.count > 64 || routes.count > 4096 {
            issue(.limitExceeded)
        }
    }

    private mutating func checkInterface() {
        if let port = profile.interface.listenPort, port == 0 {
            issue(.invalidPort)
        }
        let hasIPv6Address = profile.interface.addresses.contains(where: \.isIPv6)
        if let mtu = profile.interface.mtu, !(1280 ... 1500).contains(mtu) {
            issue(.invalidMTU)
        }
        if fullIPv4, !hasIPv6Address, profile.protection.ipv6Policy == .tunnel {
            issue(.ipv6PolicyRequired)
        }
        if publicKeysInUse.contains(profile.interface.publicKey) {
            issue(.keyInUseElsewhere, .warning)
        }
    }

    private mutating func checkPeers() {
        if Set(profile.peers.map(\.publicKey)).count != profile.peers.count {
            issue(.duplicatePeer)
        }
        if carrierActive, profile.peers.count != 1 {
            issue(.carrierRequiresSinglePeer)
        }
        if carrierActive,
           profile.peers.contains(where: { ($0.persistentKeepalive ?? 0) > 25 })
        {
            issue(.keepaliveClampedByCarrier, .warning)
        }
        for peer in profile.peers {
            if let endpoint = peer.endpoint {
                do { try endpoint.validate() }
                catch { issue(error == .invalidPort ? .invalidPort : .invalidEndpoint) }
            }
            if peer.hasPresharedKey != (profile.secrets.presharedKeys[peer.publicKey] != nil) {
                issue(.invalidKey)
            }
        }
    }

    private mutating func checkDNS() {
        if profile.interface.dns.contains(where: { server in !routes.contains { $0.contains(server.address) } }) {
            issue(
                .dnsOutsideAllowedIPs,
                .warning,
            )
        }
        if profile.protection.dnsPolicy == .systemDefault {
            issue(.dnsOutsideAllowedIPs, .warning, message: UserStrings.systemDNSWarning)
        }
        if profile.interface.searchDomains.contains(where: { !PublicFieldSafety.isSearchDomain($0) }) {
            issue(.invalidDNS)
        }
        if profile.interface.searchDomains.contains(where: Self.hasControl) {
            issue(.controlCharacter)
        }
        if case let .split(domains) = profile.protection.dnsPolicy {
            if domains.isEmpty || domains.contains(where: { !PublicFieldSafety.isSearchDomain($0) }) {
                issue(.invalidDNS)
            }
            if domains.contains(where: Self.hasControl) {
                issue(.controlCharacter)
            }
        }
    }

    private mutating func checkTransport() {
        let ids = Set(profile.transport.candidates.map(\.id))
        var invalid = profile.transport.candidates.isEmpty || ids.count != profile.transport.candidates.count
        switch profile.transport.selection {
        case let .manual(id): invalid = invalid || !ids.contains(id)
        case let .automatic(policy):
            invalid = invalid || policy.unhealthyWindows < 1 || policy.recoveryWindow <= .zero || policy.failedEpisodeBackoff < .zero ||
                policy.automaticFailback || Set(policy.order).count != policy.order.count || Set(policy.order) != ids
        }
        if invalid {
            issue(.invalidEndpoint, message: UserStrings.invalidTransport)
        }
    }

    /// ADR-030: an include or exclude list holds 1 to 64 distinct SSIDs of 1 to 32 UTF-8 bytes without control characters.
    private mutating func checkOnDemand() {
        guard case let .interfaces(interfaces) = profile.onDemand, let match = interfaces.ssidMatch,
              match != .anySSID else { return }
        let ssids = match.ssids
        if !(1 ... 64).contains(ssids.count) || ssids.contains(where: { !(1 ... 32).contains($0.utf8.count) }) {
            issue(.limitExceeded)
        }
        if ssids.contains(where: Self.hasControl) {
            issue(.controlCharacter)
        }
        if Set(ssids).count != ssids.count {
            issue(.duplicateKey)
        }
    }

    /// DEC-087: at most 64 entries; no default route; valid host names; nothing that would carry the tunnel's own
    /// addresses, DNS servers or endpoints outside it; and a carved route plan within the 4096-route limit.
    private mutating func checkExclusions() {
        let exclusions = profile.exclusions
        guard !exclusions.isEmpty else { return }
        if exclusions.count > TunnelExclusions.maximumEntries {
            issue(.limitExceeded, message: UserStrings.exclusionLimit)
        }
        if Set(exclusions.ranges.map(\.network)).count != exclusions.ranges.count || Set(exclusions.hostNames).count != exclusions
            .hostNames.count || Set(exclusions.ports).count != exclusions.ports.count
        {
            issue(.duplicateKey)
        }
        checkExclusionPorts(exclusions.ports)
        // NE ignores excluded routes under includeAllNetworks; a warning, never an error, and the setting stays.
        if profile.protection.ios.includeAllNetworks, !exclusions.ranges.isEmpty || !exclusions.hostNames.isEmpty {
            issue(.unsupportedSetting, .warning, message: UserStrings.exclusionsForceAllTrafficWarning)
        }
        if exclusions.ranges.contains(where: { $0.prefixLength == 0 }) {
            issue(.invalidCIDR, message: UserStrings.exclusionDefaultRoute)
        }
        if exclusions.hostNames.contains(where: { name in
            name.utf8.count > TunnelExclusions.maximumHostNameLength || Self.hasControl(name) ||
                (try? TunnelExclusions.entry(name)) != .hostName(name)
        }) {
            issue(.invalidEndpoint, message: UserStrings.exclusionHostName)
        }
        let ranges = exclusions.ranges.filter { $0.prefixLength > 0 }
        var own = profile.interface.addresses.map(\.network) + profile.interface.dns.map(\.address)
        own += profile.peers.compactMap { peer in peer.endpoint.flatMap { try? IPAddressRange($0.host) } }
        let endpointNames = Set(profile.peers.compactMap { $0.endpoint?.host.lowercased() })
        if own.contains(where: { address in ranges.contains { $0.overlaps(address) } }) ||
            exclusions.hostNames.contains(where: endpointNames.contains)
        {
            issue(.invalidCIDR, message: UserStrings.exclusionOverlapsTunnel)
        }
        // The Mac plan also carries ::/0 for blockOutside without IPv6 routes (TunnelController.routes).
        let planned = profile.protection.ipv6Policy == .blockOutside && !routes.contains(where: \.isIPv6) ? routes + [.allIPv6] : routes
        if TunnelExclusions.carve(planned, excluding: ranges).count > 4096 {
            issue(.limitExceeded, message: UserStrings.exclusionLimit)
        }
    }

    /// DEC-126: at most 16 port entries; the engine's listen port is never excluded (its traffic belongs to the tunnel).
    private mutating func checkExclusionPorts(_ ports: [PortExclusion]) {
        if ports.count > TunnelExclusions.maximumPortEntries {
            issue(.limitExceeded, message: UserStrings.exclusionPortLimit)
        }
        if ports.contains(where: \.touchesEphemeralRange) {
            issue(.exclusionPortEphemeral, message: UserStrings.exclusionPortEphemeral)
        }
        if let listen = profile.interface.listenPort, ports.contains(where: { $0.contains(listen) }) {
            issue(.invalidPort, message: UserStrings.exclusionPortListen)
        }
    }

    private static func hasControl(_ text: String) -> Bool {
        text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    private static func coversIPv4Default(_ ranges: [IPAddressRange]) -> Bool {
        let intervals = ranges.compactMap(\.ipv4Bounds).sorted { $0.lowerBound < $1.lowerBound }
        var next: UInt64 = 0
        for interval in intervals {
            if interval.lowerBound > next {
                return false
            }
            next = max(next, interval.upperBound + 1)
            if next == 1 << 32 {
                return true
            }
        }
        return false
    }
}
