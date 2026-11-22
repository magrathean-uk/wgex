// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

/// DEC-126 port exclusions: entry parsing, validation, decoding and the wg-quick round trip.
private struct PortExclusionTests {
    private static func parsed(interface: String = "") throws -> ParsedConfiguration {
        var bytes = try Array(CodecFixtures.minimal(interface: interface).utf8)
        return try parseWgQuick(&bytes)
    }

    private static func messages(_ profile: TunnelProfile) -> [String] {
        profile.validate().filter { $0.severity == .error }.map(\.message)
    }

    @Test
    func `port entries parse to canonical form and malformed ports are refused as ports`() throws {
        #expect(try TunnelExclusions.entry("1911") == .port(PortExclusion(lower: 1911)))
        #expect(try TunnelExclusions.entry(" 1911/TCP ") == .port(PortExclusion(lower: 1911, transport: .tcp)))
        #expect(try TunnelExclusions.entry("6881-6889/udp") == .port(PortExclusion(lower: 6881, upper: 6889, transport: .udp)))
        #expect(try TunnelExclusions.entry("1-1024").text == "1-1024")
        #expect(try TunnelExclusions.entry("65535/udp").text == "65535/udp")
        #expect(try TunnelExclusions.entry("80-80").text == "80")
        for bad in ["0", "65536", "1911/icmp", "1911/", "10-9", "1-1025", "1911-", "1-2-3", "1911/tcp/udp", "99999999"] {
            #expect(throws: ConfigurationError.invalidPort) { try TunnelExclusions.entry(bad) }
        }
        // Addresses and host names keep their meaning.
        #expect(try TunnelExclusions.entry("192.0.2.7") == .range(IPAddressRange("192.0.2.7/32")))
        #expect(try TunnelExclusions.entry("1vault.example") == .hostName("1vault.example"))
        let value = try TunnelExclusions(entries: ["1911", "1911", "6881-6889/udp", "example.com"])
        #expect(value.ports.map(\.text) == ["1911", "6881-6889/udp"])
        #expect(value.count == 1)
        #expect(value.entries.map(\.text) == ["example.com", "1911", "6881-6889/udp"])
    }

    @Test
    func `a document without ports decodes as empty, a value round trips and a bad stored range is refused`() throws {
        #expect(try JSONDecoder().decode(TunnelExclusions.self, from: Data(#"{"ranges":[],"hostNames":["example.com"]}"#.utf8))
            .ports.isEmpty)
        var profile = try Self.parsed().profile
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "1911/tcp", "6881-6889"])
        #expect(try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(profile)) == profile)
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(PortExclusion.self, from: Data(#"{"lower":1,"upper":2000}"#.utf8))
        }
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(PortExclusion.self, from: Data(#"{"lower":0}"#.utf8)) }
    }

    @Test
    func `validation accepts ordinary ports and refuses too many, duplicates and the listen port`() throws {
        var profile = try Self.parsed().profile
        profile.interface.listenPort = 51820
        profile.exclusions = try TunnelExclusions(entries: ["1911", "6881-6889/udp"])
        #expect(Self.messages(profile).isEmpty)
        profile.exclusions.ports = try (1 ... 17).map { try PortExclusion(lower: UInt16(2000 + $0)) }
        #expect(Self.messages(profile).contains(UserStrings.exclusionPortLimit))
        profile.exclusions.ports = try [PortExclusion(lower: 1911), PortExclusion(lower: 1911)]
        #expect(profile.validate().contains { $0.code == .duplicateKey })
        profile.exclusions.ports = try [PortExclusion(lower: 51000, upper: 52000, transport: .udp)]
        #expect(Self.messages(profile).contains(UserStrings.exclusionPortListen))
        profile.exclusions.ports = try [PortExclusion(lower: 51820, transport: .tcp)]
        #expect(Self.messages(profile).contains(UserStrings.exclusionPortListen))
    }

    @Test
    func `wg-quick import reads ports from the exclusion line and export writes them back`() throws {
        let parsed = try Self.parsed(interface: "# WGEX-Exclude = 1911, example.com\n# WGEX-Exclude = 6881-6889/UDP, 192.0.2.0/24")
        #expect(parsed.profile.exclusions.ports.map(\.text) == ["1911", "6881-6889/udp"])
        let text = serialiseWgQuick(parsed.profile)
        #expect(text.contains("# WGEX-Exclude = 192.0.2.0/24, example.com, 1911, 6881-6889/udp\n"))
        let normalised = try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
        var bytes = normalised.bytes.withUnsafeBytes { Array($0) }
        #expect(try parseWgQuick(&bytes).profile.exclusions == parsed.profile.exclusions)
        #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = 70000") }
        let many = (1 ... 17).map { String(3000 + $0) }.joined(separator: ", ")
        #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = \(many)") }
    }

    @Test
    func `ephemeral ports 49152 and above are refused by validation, import and wg-quick parse`() throws {
        var profile = try Self.parsed().profile
        for bad in ["51413", "49000-49200", "49152", "65535/udp", "60000-60010/tcp"] {
            profile.exclusions = try TunnelExclusions(entries: [bad])
            let issues = profile.validate().filter { $0.code == .exclusionPortEphemeral }
            #expect(issues.count == 1, "\(bad)")
            #expect(issues.first?.severity == .error)
            #expect(issues.first?.message == UserStrings.exclusionPortEphemeral)
            #expect(throws: ConfigParseError.self) { _ = try Self.parsed(interface: "# WGEX-Exclude = \(bad)") }
        }
        for good in ["1911", "6881-6889/udp", "49151", "49000-49151/tcp"] {
            profile.exclusions = try TunnelExclusions(entries: [good])
            #expect(!profile.validate().contains { $0.code == .exclusionPortEphemeral }, "\(good)")
            #expect(try Self.parsed(interface: "# WGEX-Exclude = \(good)").profile.exclusions.ports.count == 1)
        }
        #expect(UserStrings.exclusionPortEphemeral.contains("49152"))
        #expect(UserStrings.exclusionPortEphemeral.contains("below 49152"))
    }
}
