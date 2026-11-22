// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct Guest5DNSAndStatusTests {
    @Test(arguments: [1, 2, 3, 4, 999])
    func `future protection notes decode as absent without losing status`(raw: Int) throws {
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(TunnelStatus.idle)) as? [String: Any])
        object["protectionNote"] = raw
        let status = try JSONDecoder().decode(TunnelStatus.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(status.phase == .idle)
        #expect(status.protectionNote == ProtectionNote(rawValue: raw))
    }

    @Test(arguments: ["8 (utun7)", "7 (utun8)", "invalid", "7 (utun7)"])
    func `D5 published interface identity cannot be borrowed from another resolver`(_ identity: String) async throws {
        let h = try NetworkPortHarness()
        let configuration = DNSConfiguration(servers: ["10.77.0.1"], searchDomains: [], matchDomains: [""])
        try h.journal.mutate(generation: h.generation) { $0.resources[0].dns = configuration }
        let listing = try NetworkPortHarness.fixture(Self.realCapture)
            .replacingOccurrences(of: "  order    : 101600", with: "  if_index : " + identity + "\n  order    : 101600")
        let session = FakeDNSSession(listing: listing)
        let verified = DNSConfigurator(journal: h.journal, session: session)
        try await verified.apply(configuration, generation: h.generation)
        if identity == "7 (utun7)" {
            try await verified.verify(h.resources)
        } else {
            await #expect(throws: (any Error).self) { try await verified.verify(h.resources) }
        }
    }

    /// M1-18: `scutil --dns` captured in guest run 6 while the daemon reported active/protected (M1-16 run6,
    /// connected-2026-10-29/scutil-dns.txt, copied verbatim; lab addresses only, no service key). It replaces the
    /// synthetic run-5 fixture, whose order 102000 and section shape were reconstructed rather than observed.
    static let realCapture = "DNS/guest6-run6-connected-scutil.txt"

    @Test
    func `D5 the real run 6 resolver is supplemental, order 101600, without if_index and not scoped`() throws {
        let records = try ScutilDNSParser.parse(NetworkPortHarness.fixture(Self.realCapture))
        let ours = records.filter { $0.servers == ["10.77.0.1"] }
        #expect(ours.count == 1)
        let resolver = try #require(ours.first)
        #expect(resolver.supplemental)
        #expect(resolver.order == 101_600)
        #expect(resolver.interfaceIndex == nil)
        #expect(resolver.interfaceName == nil)
        #expect(resolver.domain.isEmpty)
        #expect(!resolver.scoped)
        // The scoped section holds only the underlay's own resolver (en0, if_index 6).
        let scoped = records.filter(\.scoped)
        #expect(scoped.map(\.servers) == [["192.168.64.1"]])
        #expect(scoped.map(\.interfaceIndex) == [6])
        #expect(scoped.map(\.interfaceName) == ["en0"])
        // The parser needs no if_index to verify the published resolver; neither interface argument is consulted.
        let configuration = DNSConfiguration(servers: ["10.77.0.1"], searchDomains: [], matchDomains: [""])
        let expected = try SyntheticDNSValue(configuration: configuration, searchOrder: 1)
        #expect(try ScutilDNSParser.verifies(expected, in: NetworkPortHarness.fixture(Self.realCapture)))
        #expect(try ScutilDNSParser.verifies(
            expected, in: NetworkPortHarness.fixture(Self.realCapture), interfaceName: "utun4", interfaceIndex: 12,
        ))
    }

    @Test
    func `D5 real run 6 supplemental order verifies only with the actual owned key`() async throws {
        let h = try NetworkPortHarness()
        let configuration = DNSConfiguration(servers: ["10.77.0.1"], searchDomains: [], matchDomains: [""])
        try h.journal.mutate(generation: h.generation) { $0.resources[0].dns = configuration }
        let session = try FakeDNSSession(listing: NetworkPortHarness.fixture(Self.realCapture))
        let dns = DNSConfigurator(journal: h.journal, session: session)
        try await dns.apply(configuration, generation: h.generation)
        try await dns.verify(h.resources)
        let key = try #require(h.resources.dnsKey)
        let value = try #require(await session.read(key: key))
        await session.remove(key: key)
        await session.addTemporary(key: "State:/Network/Service/SYNTHETIC-OTHER-OWNER/DNS", value: value)
        await #expect(throws: DaemonFailure.portNotOwned) { try await dns.verify(h.resources) }
    }

    @Test
    func `D10 a failed network verification retains its note after blocking rollback`() async throws {
        let h = try ControllerHarness(); try await h.install()
        h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { _ = try await h.start() }
        #expect(await h.controller.status.protection == .blocked)
        #expect(await h.controller.status.protectionNote == .verificationFailed)
        await h.controller.cancelBackgroundWork()
    }

    @Test(arguments: [DaemonFailure.pfVerification, DaemonFailure(code: .pfCanaryFailed)])
    func `D10 verification and canary failures remain distinct from missing DNS`(_ failure: DaemonFailure) async throws {
        let h = try ControllerHarness()
        await h.controller.setPolicyFailure(failure)
        let status = await h.controller.status
        #expect(status.protectionNote == (failure.kind == .pfCanaryFailed ? .canaryFailed : .verificationFailed))
        let bytes = try WireCodec.encode(Reply.status(status))
        #expect(try WireCodec.decode(Reply.self, from: bytes) == .status(status))
        var legacy = Envelope(body: .status); legacy.protocolVersion = Envelope.currentProtocolVersion
        #expect(try Envelope.decode(legacy.encoded()).body == .status)
    }

    @Test
    func `D10 DNS less status includes its own additive protection note`() async throws {
        let h = try ControllerHarness()
        var profile = h.profile; profile.interface.dns = []
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        _ = try await h.start()
        let qualified = await h.controller.qualifyStatus(h.controller.status, profileID: profile.id)
        #expect(qualified.status.protection == .unknown)
        #expect(qualified.status.protectionNote?.rawValue == 2)
        await h.controller.cancelBackgroundWork()
    }
}
