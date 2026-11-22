// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXNEProvider

private struct SettingsGoldenTests {
    @Test
    func `explicit MTU optional DNS split routes and disabled LAN exclusions are preserved`() throws {
        var profile = try GoldenFixture.profile()
        profile.interface.mtu = 1500
        profile.interface.dns = []
        profile.protection.tv.allowLAN = false
        profile.peers[0].allowedIPs = try ["10.9.0.0/16", "fd01::/48"].map(IPAddressRange.init)
        let settings = try NESettingsGenerator.generate(profile, platform: .tvOS)
        #expect(settings.mtu == 1500)
        #expect(settings.dns == nil)
        #expect(settings.ipv4?.excludedRoutes.isEmpty == true)
        #expect(settings.ipv6?.excludedRoutes.isEmpty == true)
        #expect(settings.ipv4?.includedRoutes.map(\.stringRepresentation) == ["10.9.0.0/16"])
        #expect(settings.ipv6?.includedRoutes.map(\.stringRepresentation) == ["fd01::/48"])
        #expect(try NESettingsGenerator.generate(profile, platform: .tvOS, carrier: true).mtu == 1420)
    }

    @Test(arguments: GoldenFixture.names)
    func `RT19 network settings match bytes on both platforms`(_ name: String) throws {
        for platform in [ProfilePlatform.iOS, .tvOS] {
            let value = try NESettingsGenerator.generate(GoldenFixture.profile(name), platform: platform, carrier: name == "carrier")
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let suffix = platform == .iOS ? "ios" : "tvos"
            let url = try #require(Bundle.module.url(forResource: "\(name)-\(suffix)", withExtension: "json", subdirectory: "Goldens"))
            #expect(try encoder.encode(value) == Data(contentsOf: url))
        }
    }
}
