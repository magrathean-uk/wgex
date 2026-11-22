// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXNEClient

private struct ProtocolGoldenTests {
    /// One iOS golden per official Cellular and Wi-Fi combination (M06-T01); SSIDs are given unsorted.
    static let onDemandCombinations: [(name: String, policy: OnDemandIOSInterfaces)] = [
        ("cellular", .cellularOnly),
        ("wifi-any", .wifiOnly(.anySSID)),
        ("wifi-only", .wifiOnly(.onlySSIDs(["Z", "A"]))),
        ("wifi-except", .wifiOnly(.exceptSSIDs(["Z", "A"]))),
        ("wifi-cellular-any", .wifiOrCellular(.anySSID)),
        ("wifi-cellular-only", .wifiOrCellular(.onlySSIDs(["Z", "A"]))),
        ("wifi-cellular-except", .wifiOrCellular(.exceptSSIDs(["Z", "A"]))),
    ]

    private static func encoded(_ value: ProtocolConfiguration) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    private static func golden(_ name: String) throws -> Data {
        let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Goldens"))
        return try Data(contentsOf: url)
    }

    private static let identifiers = BuildIdentifiers(base: "test.wgex", team: "TEST")

    @Test(arguments: GoldenFixture.names)
    func `RT19 protocol values match bytes on both platforms`(_ name: String) throws {
        for platform in [ProfilePlatform.iOS, .tvOS] {
            let value = try ProtocolConfigurationBuilder.build(
                GoldenFixture.profile(name),
                platform: platform,
                identifiers: Self.identifiers,
            )
            let suffix = platform == .iOS ? "ios" : "tvos"
            #expect(try Self.encoded(value) == Self.golden("\(name)-\(suffix)"))
        }
    }

    @Test(arguments: Self.onDemandCombinations.map(\.name))
    func `iOS on-demand combinations match bytes`(_ name: String) throws {
        let policy = try #require(Self.onDemandCombinations.first { $0.name == name }?.policy)
        var profile = try GoldenFixture.profile()
        profile.onDemand = .iosInterfaces(policy)
        let value = ProtocolConfigurationBuilder.build(profile, platform: .iOS, identifiers: Self.identifiers)
        #expect(try Self.encoded(value) == Self.golden("ondemand-\(name)-ios"))
        let tv = ProtocolConfigurationBuilder.build(profile, platform: .tvOS, identifiers: Self.identifiers)
        #expect(tv.onDemandRules.isEmpty)
    }
}
