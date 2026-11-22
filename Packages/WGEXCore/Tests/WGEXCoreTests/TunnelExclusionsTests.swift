// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

/// DEC-087 exclusions: entry parsing, validation, route carving, decoding and the wg-quick extension.
private struct TunnelExclusionsTests {
    private static func parsed(interface: String = "", peer: String = "") throws -> ParsedConfiguration {
        var bytes = try Array(CodecFixtures.minimal(interface: interface, peer: peer).utf8)
        return try parseWgQuick(&bytes)
    }

    private static func codes(_ profile: TunnelProfile) -> [String] {
        profile.validate().filter { $0.severity == .error }.map(\.message)
    }

    /// M08-T09 (lab run 3, EXCL-ADDR): the Mac import saved a rebuilt profile without its exclusions.
    @Test
    func `the import's saved copy keeps the exclusions under its new id`() throws {
        let parsed = try Self.parsed(interface: "# WGEX-Exclude = 198.51.100.0/24, example.com")
        #expect(parsed.profile.exclusions.count == 2)
        let id = UUID()
        let options = MacProfileOptions(startBeforeLogin: true)
        let copy = parsed.profile.importedCopy(id: id, macOptions: options)
        #expect(copy.id == id && copy.macOptions == options)
        #expect(copy.exclusions == parsed.profile.exclusions)
        #expect(copy.interface == parsed.profile.interface && copy.peers == parsed.profile.peers)
        #expect(copy.protection == parsed.profile.protection && copy.secrets == parsed.profile.secrets)
    }

    @Test
    func `entries parse addresses ranges and host names into canonical form`() throws {
        #expect(try TunnelExclusions.entry("192.0.2.7") == .range(IPAddressRange("192.0.2.7/32")))
        #expect(try TunnelExclusions.entry(" 192.0.2.77/24 ") == .range(IPAddressRange("192.0.2.0/24")))
        #expect(try TunnelExclusions.entry("2001:DB8::1/48") == .range(IPAddressRange("2001:db8::/48")))
        #expect(try TunnelExclusions.entry("Example.COM.") == .hostName("example.com"))
        for bad in [
            "",
            "192.0.2.300",
            "10.0.0.0/33",
            "fe80::1%en0",
            "-bad.example",
            "a..b",
            "1.2.3",
            "host/24",
            String(repeating: "a", count: 254),
        ] {
            #expect(throws: ConfigurationError.self) { try TunnelExclusions.entry(bad) }
        }
        let value = try TunnelExclusions(entries: ["192.0.2.1", "192.0.2.1/32", "example.com", "EXAMPLE.com"])
        #expect(value.count == 2)
        #expect(value.entries.map(\.text) == ["192.0.2.1", "example.com"])
    }

    @Test
    func `a profile document without exclusions decodes as empty and a value round trips`() throws {
        var profile = try Self.parsed().profile
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as? [String: Any])
        object.removeValue(forKey: "exclusions")
        let legacy = try JSONDecoder().decode(TunnelProfile.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(legacy.exclusions == .empty)
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "example.org"])
        #expect(try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(profile)) == profile)
        #expect(try JSONDecoder().decode(TunnelExclusions.self, from: Data("{}".utf8)) == .empty)
    }

    @Test
    func `validation accepts ordinary exclusions`() throws {
        var profile = try Self.parsed(peer: "Endpoint = 203.0.113.9:51820").profile
        profile.exclusions = try TunnelExclusions(entries: ["10.77.0.128/25", "198.51.100.0/24", "2001:db8::/32", "example.com"])
        #expect(Self.codes(profile).isEmpty)
    }

    /// M08-R01 F2: Force all traffic with address or name exclusions warns and never errors; ports alone do not warn.
    @Test
    func `force all traffic with exclusions is a warning, not an error`() throws {
        var profile = try Self.parsed(peer: "Endpoint = 203.0.113.9:51820").profile
        profile.protection.ios.includeAllNetworks = true
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "example.com"])
        #expect(Self.codes(profile).isEmpty)
        let warnings = profile.validate().filter { $0.severity == .warning }
        #expect(warnings.contains { $0.code == .unsupportedSetting && $0.message == UserStrings.exclusionsForceAllTrafficWarning })
        #expect(profile.protection.ios.includeAllNetworks)
        profile.exclusions = try TunnelExclusions(entries: ["1911"])
        #expect(!profile.validate().contains { $0.message == UserStrings.exclusionsForceAllTrafficWarning })
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24"])
        profile.protection.ios.includeAllNetworks = false
        #expect(!profile.validate().contains { $0.message == UserStrings.exclusionsForceAllTrafficWarning })
    }

    @Test(arguments: [
        ("0.0.0.0/0", UserStrings.exclusionDefaultRoute),
        ("::/0", UserStrings.exclusionDefaultRoute),
        ("10.77.0.2", UserStrings.exclusionOverlapsTunnel),
        ("10.77.0.0/16", UserStrings.exclusionOverlapsTunnel),
        ("203.0.113.0/24", UserStrings.exclusionOverlapsTunnel),
        ("vpn.example.net", UserStrings.exclusionOverlapsTunnel),
        ("10.9.9.9", UserStrings.exclusionOverlapsTunnel),
    ])
    func `validation refuses exclusions that cover everything or the tunnel itself`(entry: String, message: String) throws {
        var profile = try Self.parsed(interface: "DNS = 10.9.9.9", peer: "Endpoint = 203.0.113.9:51820").profile
        if entry.contains(".net") {
            profile.peers[0].endpoint = try Endpoint("vpn.example.net:51820")
        }
        profile.exclusions = try TunnelExclusions(entries: [entry])
        #expect(Self.codes(profile).contains(message))
    }

    @Test
    func `validation refuses too many entries invalid names and duplicates`() throws {
        var profile = try Self.parsed().profile
        profile.exclusions.ranges = try (0 ..< 65).map { try IPAddressRange("198.51.100.\($0)") }
        #expect(Self.codes(profile).contains(UserStrings.exclusionLimit))
        profile.exclusions = TunnelExclusions(hostNames: ["bad name"])
        #expect(Self.codes(profile).contains(UserStrings.exclusionHostName))
        profile.exclusions = TunnelExclusions(hostNames: ["example.com", "example.com"])
        #expect(profile.validate().contains { $0.code == .duplicateKey })
    }

    @Test
    func `the route limit counts the IPv6 routes blockOutside adds`() throws {
        var profile = try Self.parsed().profile
        profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/0")]
        // Hosts spread across separate subtrees so carving ::/0 around them needs over 4096 routes.
        profile.exclusions.ranges = try (0 ..< 64).map { try IPAddressRange("\(String(0x2000 + $0 * 0x40, radix: 16))::1") }
        profile.protection.ipv6Policy = .allowOutside
        #expect(!Self.codes(profile).contains(UserStrings.exclusionLimit))
        profile.protection.ipv6Policy = .blockOutside
        #expect(Self.codes(profile).contains(UserStrings.exclusionLimit))
    }

    @Test
    func `carving keeps a family without exclusions unchanged and never yields a default route`() throws {
        let full = try ["0.0.0.0/0", "::/0"].map(IPAddressRange.init)
        let carved = try TunnelExclusions.carve(full, excluding: [IPAddressRange("192.0.2.0/24")])
        #expect(carved.filter(\.isIPv6) == [full[1]])
        let v4 = carved.filter { !$0.isIPv6 }
        #expect(v4.count == 24)
        #expect(v4.allSatisfy { $0.prefixLength > 0 })
        let hole = try IPAddressRange("192.0.2.0/24"), kept = try IPAddressRange("192.0.3.1/32")
        #expect(!v4.contains { $0.overlaps(hole) })
        #expect(v4.contains { $0.contains(kept) })
        // An exclusion outside the routes leaves a split full tunnel as two halves, not a default route.
        let halves = try ["0.0.0.0/1", "128.0.0.0/1"].map(IPAddressRange.init)
        #expect(try TunnelExclusions.carve(halves, excluding: [IPAddressRange("2001:db8::/32")]) == halves)
        #expect(try TunnelExclusions.carve(halves, excluding: [IPAddressRange("10.0.0.0/8")]).allSatisfy { $0.prefixLength > 0 })
        #expect(TunnelExclusions.carve(halves, excluding: []) == halves)
    }

    @Test
    func `wg-quick import reads the comment extension and export writes it back`() throws {
        let parsed = try Self.parsed(interface: "# WGEX-Exclude = 198.51.100.0/24, example.com\n#wgex-exclude=2001:db8::1")
        #expect(parsed.profile.exclusions.entries.map(\.text) == ["198.51.100.0/24", "2001:db8::1", "example.com"])
        let text = serialiseWgQuick(parsed.profile)
        #expect(text.contains("# WGEX-Exclude = 198.51.100.0/24, 2001:db8::1, example.com\n"))
        let normalised = try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
        var bytes = normalised.bytes.withUnsafeBytes { Array($0) }
        let again = try parseWgQuick(&bytes)
        #expect(again.profile.exclusions == parsed.profile.exclusions)
        // The retained original keeps the comment byte for byte.
        #expect(parsed.original.text.contains("# WGEX-Exclude = 198.51.100.0/24, example.com"))
    }

    @Test
    func `the extension is only read in the interface section and plain comments stay comments`() throws {
        let peerOnly = try Self.parsed(interface: "# a note = not an exclusion", peer: "# WGEX-Exclude = 198.51.100.0/24")
        #expect(peerOnly.profile.exclusions == .empty)
        #expect(!serialiseWgQuick(peerOnly.profile).contains("WGEX-Exclude"))
        #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = 10.0.0.0/33") }
        let many = (0 ..< 65).map { "198.51.100.\($0)" }.joined(separator: ", ")
        #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = \(many)") }
        let key = try CodecFixtures.key("client2.key")
        #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = \(key)") }
    }
}
