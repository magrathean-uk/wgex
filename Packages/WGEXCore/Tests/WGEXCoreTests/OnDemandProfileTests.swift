// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

/// ADR-030: the additive macOS policy case, its SSID list validation and the status fields.
private struct OnDemandProfileTests {
    private func profile(_ policy: OnDemandPolicy) throws -> TunnelProfile {
        var profile = try parseWgQuick(Array(CodecFixtures.minimal().utf8)).profile
        profile.onDemand = policy
        return profile
    }

    private func codes(_ policy: OnDemandPolicy) throws -> Set<ConfigDiagnostic.Code> {
        try Set(profile(policy).validate().filter { $0.severity == .error }.map(\.code))
    }

    @Test
    func `interfaces policy round-trips through the profile document`() throws {
        for policy: OnDemandPolicy in [
            .interfaces(.ethernetOnly), .interfaces(.wifiOnly(.anySSID)), .interfaces(.wifiOnly(.onlySSIDs(["Home"]))),
            .interfaces(.wifiOrEthernet(.exceptSSIDs(["Office", "Home"]))),
        ] {
            let original = try profile(policy)
            let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(original))
            #expect(decoded.onDemand == policy)
            #expect(decoded.schemaVersion == TunnelProfile.currentSchemaVersion)
        }
    }

    @Test
    func `valid SSID lists and SSID-free options pass`() throws {
        #expect(try codes(.interfaces(.ethernetOnly)).isEmpty)
        #expect(try codes(.interfaces(.wifiOrEthernet(.anySSID))).isEmpty)
        #expect(try codes(.interfaces(.wifiOnly(.onlySSIDs([String(repeating: "x", count: 32)])))).isEmpty)
        #expect(try codes(.interfaces(.wifiOnly(.exceptSSIDs((1 ... 64).map { "n\($0)" })))).isEmpty)
    }

    @Test
    func `SSID lists are bounded, distinct and free of control characters`() throws {
        #expect(try codes(.interfaces(.wifiOnly(.onlySSIDs([])))).contains(.limitExceeded))
        #expect(try codes(.interfaces(.wifiOnly(.onlySSIDs((1 ... 65).map { "n\($0)" })))).contains(.limitExceeded))
        #expect(try codes(.interfaces(.wifiOnly(.exceptSSIDs([""])))).contains(.limitExceeded))
        // 33 bytes of UTF-8 in 11 characters.
        #expect(try codes(.interfaces(.wifiOrEthernet(.onlySSIDs([String(repeating: "\u{20AC}", count: 11)])))).contains(.limitExceeded))
        #expect(try codes(.interfaces(.wifiOrEthernet(.exceptSSIDs(["a\nb"])))).contains(.controlCharacter))
        #expect(try codes(.interfaces(.wifiOnly(.onlySSIDs(["Home", "Home"])))).contains(.duplicateKey))
        #expect(try !codes(.interfaces(.wifiOnly(.onlySSIDs(["Home", "home"])))).contains(.duplicateKey))
    }

    @Test
    func `listed SSIDs join the public-field key check`() throws {
        let key = Data(repeating: 0xFB, count: 32).base64EncodedString()
        for policy: OnDemandPolicy in [.interfaces(.wifiOnly(.onlySSIDs([key]))), .interfaces(.wifiOrEthernet(.exceptSSIDs([key])))] {
            #expect(try profile(policy).validate().contains { $0.code == .invalidKey && $0.message == UserStrings.secretInPublicField })
        }
    }

    @Test
    func `requiresSSID is true only for non-empty lists`() {
        #expect(!OnDemandPolicy.interfaces(.ethernetOnly).requiresSSID)
        #expect(!OnDemandPolicy.interfaces(.wifiOnly(.anySSID)).requiresSSID)
        #expect(OnDemandPolicy.interfaces(.wifiOnly(.onlySSIDs(["A"]))).requiresSSID)
        #expect(OnDemandPolicy.always(exceptSSIDs: ["A"]).requiresSSID)
        #expect(!OnDemandPolicy.always(exceptSSIDs: []).requiresSSID)
    }

    @Test
    func `status carries on-demand state without an SSID and decodes legacy snapshots`() throws {
        var status = TunnelStatus.idle
        status.onDemand = OnDemandStatus(
            armedProfileID: UUID(), activated: true, network: .wifi, ssid: .unavailable(.timedOut),
            decision: .hold(.ssidUnavailable), evaluatedAtContinuous: 12,
        )
        let bytes = try JSONEncoder().encode(status)
        #expect(try JSONDecoder().decode(TunnelStatus.self, from: bytes) == status)
        let legacy = try JSONEncoder().encode(TunnelStatus.idle)
        #expect(try JSONDecoder().decode(TunnelStatus.self, from: legacy).onDemand == nil)
        var other = status; other.onDemand?.decision = .connect
        #expect(!status.hasSameState(as: other))
        #expect(StopReason(rawValue: "onDemand") == .onDemand)
    }
}
