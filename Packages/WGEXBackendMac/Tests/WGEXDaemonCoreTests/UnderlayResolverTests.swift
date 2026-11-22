// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

private struct UnderlayResolverTests {
    @Test(arguments: [false, true])
    func `engine bridge receives both bindings and primary resolvers and interleaves RFC8305 candidates`(ipv6: Bool) async throws {
        let engine =
            FakeEngineResolver(response: Data(#"{"a":["192.0.2.1","192.0.2.2","192.0.2.1"],"aaaa":["2001:db8::1","2001:db8::2"],"ttl":60}"#
                    .utf8))
        let resolver = UnderlayResolver(engine: engine)
        let underlay = UnderlaySnapshot(v4: 4, v6: ipv6 ? 6 : nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"])
        let addresses = try await resolver.resolve(host: "peer.example.test", underlay: underlay)
        #expect(addresses == (ipv6 ? ["2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"] : [
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.2",
            "2001:db8::2",
        ]))
        #expect(await engine.queries.first?.v4 == 4)
        #expect(await engine.queries.first?.v6 == (ipv6 ? 6 : nil))
        #expect(await engine.queries.first?.resolvers == ["192.0.2.53"])
    }

    @Test(arguments: [#"{"a":[],"aaaa":[],"ttl":0,"error":"nxdomain"}"#, #"{"a":["bad","192.0.2.1/32"],"ttl":60}"#, "{}", "not JSON"])
    func `invalid and failed answers never become endpoints`(response: String) async {
        let resolver = UnderlayResolver(engine: FakeEngineResolver(response: Data(response.utf8)))
        await #expect(throws: DaemonFailure.portNoAnswer) { try await resolver.resolve(
            host: "peer.example.test",
            underlay: ControllerHarness.underlay,
        ) }
        await #expect(throws: DaemonFailure.portNoAnswer) { try await resolver.resolve(host: "peer.example.test", interfaceIndex: 4) }
    }

    @Test
    func `last known good is journalled only after handshake and is tried on resolver failure`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let generation = try await harness.start()
        #expect(harness.journal.snapshot().lastGoodAddresses.isEmpty)
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: generation)
        #expect(harness.journal.snapshot().lastGoodAddresses["peer.example.test"] == ["2001:db8::1"])
        harness.trace.fail(at: "resolver.resolve")
        try await harness.controller.refreshEndpoints(generation: generation)
        #expect(await harness.controller.selectedEndpoints[peer]?.host == "2001:db8::1")
    }

    @Test
    func `DNS64 answers remain literal IPv6 candidates with no IPv4 synthesis`() async throws {
        let engine = FakeEngineResolver(response: Data(#"{"a":[],"aaaa":["64:ff9b::c000:201"],"ttl":60}"#.utf8))
        let resolver = UnderlayResolver(engine: engine)
        let underlay = UnderlaySnapshot(v4: nil, v6: 6, resolvers: ["2001:db8::53"], interfaceNames: ["en1"])
        #expect(try await resolver.resolve(host: "peer.example.test", underlay: underlay) == ["64:ff9b::c000:201"])
        #expect(await engine.queries.first?.v4 == nil)
    }

    @Test
    func `resolver TTL cache is bound to the underlay and invalidated for explicit re-resolution`() async throws {
        let clock = HostClock()
        let engine = FakeEngineResolver(response: Data(#"{"a":["192.0.2.1"],"aaaa":[],"ttl":60}"#.utf8))
        let resolver = UnderlayResolver(engine: engine, clock: clock)
        _ = try await resolver.resolve(host: "peer.example.test", underlay: ControllerHarness.underlay)
        _ = try await resolver.resolve(host: "peer.example.test", underlay: ControllerHarness.underlay)
        #expect(await engine.queries.count == 1)
        clock.advance(.seconds(60))
        _ = try await resolver.resolve(host: "peer.example.test", underlay: ControllerHarness.underlay)
        #expect(await engine.queries.count == 2)
        await resolver.invalidate()
        _ = try await resolver.resolve(host: "peer.example.test", underlay: ControllerHarness.underlay)
        #expect(await engine.queries.count == 3)
        let changed = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["en1"])
        _ = try await resolver.resolve(host: "peer.example.test", underlay: changed)
        #expect(await engine.queries.count == 4)
    }
}
