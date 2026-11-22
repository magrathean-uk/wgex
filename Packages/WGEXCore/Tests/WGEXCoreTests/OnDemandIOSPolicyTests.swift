// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

/// M06-T01: the additive iOS on-demand case and the stored encodings it must not disturb.
private struct OnDemandIOSPolicyTests {
    @Test
    func `stored legacy encodings decode unchanged`() throws {
        let cases: [(String, OnDemandPolicy)] = [
            (#"{"off":{}}"#, .off),
            (#"{"always":{"exceptSSIDs":[]}}"#, .always(exceptSSIDs: [])),
            (#"{"always":{"exceptSSIDs":["Home","Office"]}}"#, .always(exceptSSIDs: ["Home", "Office"])),
            (#"{"wifiOnly":{"exceptSSIDs":[]}}"#, .wifiOnly(exceptSSIDs: [])),
            (#"{"wifiOnly":{"exceptSSIDs":["Home"]}}"#, .wifiOnly(exceptSSIDs: ["Home"])),
            (#"{"cellularOnly":{}}"#, .cellularOnly),
        ]
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        for (json, policy) in cases {
            #expect(try JSONDecoder().decode(OnDemandPolicy.self, from: Data(json.utf8)) == policy)
            #expect(try String(decoding: encoder.encode(policy), as: UTF8.self) == json)
        }
    }

    @Test
    func `iOS shape round-trips through the profile document`() throws {
        for interfaces: OnDemandIOSInterfaces in [
            .cellularOnly, .wifiOnly(.anySSID), .wifiOnly(.onlySSIDs(["Home"])), .wifiOnly(.exceptSSIDs(["Home"])),
            .wifiOrCellular(.anySSID), .wifiOrCellular(.onlySSIDs(["Office", "Home"])), .wifiOrCellular(.exceptSSIDs(["Home"])),
        ] {
            var profile = try parseWgQuick(Array(CodecFixtures.minimal().utf8)).profile
            profile.onDemand = .iosInterfaces(interfaces)
            let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(profile))
            #expect(decoded.onDemand == .iosInterfaces(interfaces))
        }
    }

    @Test
    func `iOS SSIDs join the public-field check and never require an SSID on macOS`() throws {
        let key = Data(repeating: 0xFB, count: 32).base64EncodedString()
        var profile = try parseWgQuick(Array(CodecFixtures.minimal().utf8)).profile
        profile.onDemand = .iosInterfaces(.wifiOrCellular(.onlySSIDs([key])))
        #expect(profile.onDemand.namedSSIDs == [key])
        #expect(profile.validate().contains { $0.code == .invalidKey && $0.message == UserStrings.secretInPublicField })
        #expect(!profile.onDemand.requiresSSID)
        #expect(OnDemandPolicy.iosInterfaces(.cellularOnly).namedSSIDs.isEmpty)
        #expect(OnDemandIOSInterfaces.cellularOnly.ssidMatch == nil)
        #expect(OnDemandIOSInterfaces.wifiOnly(.exceptSSIDs(["A"])).ssidMatch == .exceptSSIDs(["A"]))
    }
}
