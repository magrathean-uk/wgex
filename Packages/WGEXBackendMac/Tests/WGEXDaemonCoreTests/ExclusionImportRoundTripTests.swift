// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// M08-T09 (lab run 3, EXCL-ADDR): exclusions imported from a file must survive the Mac import's saved copy, the profile
/// store document, the daemon request and its decoding, and then carve the route plan and render the packet-filter passes.
/// The Mac import rebuilt the profile without its exclusions, so the daemon routed and filtered the tunnel as if none were
/// listed. Rules and routes are only rendered and planned here, never applied.
@Suite(.timeLimit(.minutes(1)))
private struct ExclusionImportRoundTripTests {
    /// A full-tunnel file with one exclusion line; keys are generated, never literal.
    private static func importedFile() throws -> ParsedConfiguration {
        let privateKey = Data((1 ... 32).map { UInt8($0) }).base64EncodedString()
        let publicKey = Data((1 ... 32).map { UInt8(64 + $0) }).base64EncodedString()
        let text = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.77.0.2/32
        # WGEX-Exclude = 198.51.100.0/24
        DNS = 10.77.0.1

        [Peer]
        PublicKey = \(publicKey)
        AllowedIPs = 0.0.0.0/0
        Endpoint = 192.168.64.1:51820

        """
        var bytes = Array(text.utf8)
        return try parseWgQuick(&bytes, name: "wgex-lab-m08")
    }

    private static func context() throws -> PFContext {
        try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun4"),
            endpoints: [PFEndpoint("192.168.64.1:51820")],
            resolvers: [PFAddress("192.168.64.1")], tunnelDNS: [PFAddress("10.77.0.1")],
            lanSubnets: [IPAddressRange("192.168.64.0/24")],
            tunnelRanges: [IPAddressRange("0.0.0.0/0")],
            consoleUID: 501,
        )
    }

    @Test
    func `an imported exclusion reaches the daemon route plan and packet filter`() throws {
        let excluded = try IPAddressRange("198.51.100.0/24")
        let parsed = try Self.importedFile()
        #expect(parsed.profile.exclusions.ranges == [excluded])

        // The Mac import's saved copy (MacAppModel.importedProfile), as a new tunnel and as a replacement.
        for id in [parsed.profile.id, UUID()] {
            let saved = parsed.profile.importedCopy(id: id, macOptions: MacProfileOptions())
            #expect(saved.exclusions == parsed.profile.exclusions)

            // The app's profile store document.
            let stored = try JSONDecoder().decode(ProfileDocument.self, from: ProfileDocument(profile: saved).encoded()).profile
            #expect(stored.exclusions == parsed.profile.exclusions)

            // The daemon request the app sends and the daemon decodes.
            let wire = try Envelope(body: .installProfileCAS(stored, expectedRevision: nil)).encoded()
            guard case let .installProfileCAS(received, _) = try Envelope.decode(wire).body else {
                Issue.record("the request did not decode as installProfileCAS"); return
            }
            #expect(received.exclusions == parsed.profile.exclusions)

            // The daemon's route plan: 198.51.100.0/24 has no tunnel route, its neighbours keep theirs.
            let state = TunnelController.exclusionState(received, found: [:])
            #expect(state.ranges == [excluded])
            let routes = TunnelController.routes(received, interfaceName: "utun4", excluding: state.ranges)
            let covering = try routes.map { try IPAddressRange("\($0.destination)/\($0.prefixLength)") }
            #expect(!covering.contains { $0.overlaps(excluded) })
            #expect(try covering.contains { try $0.overlaps(IPAddressRange("198.51.101.0/24")) })
            #expect(try covering.contains { try $0.overlaps(IPAddressRange("203.0.113.9/32")) })

            // The packet filter passes the excluded range on the physical interface.
            let rules = try PacketFilterRenderer.render(
                phase: .connected, modifiers: PFModifiers(exclusions: state.ranges), context: Self.context(),
            )
            #expect(rules.contains("pass out quick on en0 inet from any to 198.51.100.0/24 no state\n"))
            #expect(rules.contains("pass in quick on en0 inet from 198.51.100.0/24 to any no state\n"))
        }
    }
}
