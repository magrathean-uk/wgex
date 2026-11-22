// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct VerifierControllerTests {
    @Test
    func `ULA service addresses do not imply an IPv6 default router`() throws {
        let fields = ["PrimaryInterface": "en0", "PrimaryService": "ula-service"]
        let snapshot = try UnderlayMonitorModel.snapshot(
            ipv4: ["PrimaryInterface": "en0"],
            ipv6: fields,
            indexes: ["en0": 4],
            resolvers: [],
            lanSubnets: [IPAddressRange("fd42:1::/64")],
        )
        #expect(snapshot.v6 == 4)
        #expect(!snapshot.ipv6DefaultRouteAvailable)
        let routed = UnderlayMonitorModel.snapshot(
            ipv4: [:],
            ipv6: fields.merging(["Router": "fe80::1%en0"]) { _, new in new },
            indexes: ["en0": 4],
            resolvers: [],
        )
        #expect(routed.ipv6DefaultRouteAvailable)
    }

    @Test
    func `retry history resets only after sixty seconds of stable active protection`() async throws {
        let h = try ControllerHarness(); try await h.install()
        var generation = try await h.start()
        await h.controller.consume(.handshakeCompleted(peer: h.profile.peers[0].publicKey, at: h.clock.wallNow), generation: generation)
        h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { try await h.controller.networkChanged(trigger: .buildChanged) }
        h.clock.advance(.seconds(5)); try await h.controller.tick()
        generation = await h.controller.currentGeneration
        await h.controller.consume(.handshakeCompleted(peer: h.profile.peers[0].publicKey, at: h.clock.wallNow), generation: generation)
        h.clock.advance(.seconds(59)); h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { try await h.controller.networkChanged(trigger: .buildChanged) }
        #expect(await h.controller.maintenanceState.retryAt == h.clock.now + .seconds(15))
        h.clock.advance(.seconds(15)); try await h.controller.tick()
        h.clock.advance(.seconds(60)); h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { try await h.controller.networkChanged(trigger: .buildChanged) }
        #expect(await h.controller.maintenanceState.retryAt == h.clock.now + .seconds(5))
    }

    @Test
    func `an idle network change supplies the next start binds and resolvers`() async throws {
        let h = try ControllerHarness(); try await h.install()
        let moved = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["moved0"])
        try await h.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: moved, satisfied: true))
        _ = try await h.start()
        let configuration = try #require(await h.ports.configurations.last)
        #expect(configuration.bindInterfaceIndexV4 == 8)
        #expect(configuration.bindInterfaceIndexV6 == 8)
        #expect(await h.ports.modifiers.last?.underlay == moved)
        #expect(await h.controller.status.protection == .protected)
    }

    @Test(arguments: [IPv6Policy.tunnel, .blockOutside, .allowOutside])
    func `ULA without an IPv6 default preserves tunnel IPv6 over an IPv4 endpoint`(policy: IPv6Policy) async throws {
        let underlay = try UnderlaySnapshot(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"],
            lanSubnets: [IPAddressRange("fd42:1::/64")], ipv6DefaultRouteAvailable: false,
        )
        let h = try ControllerHarness(underlay: underlay)
        var profile = h.profile
        profile.interface.addresses = try [IPAddressRange("10.77.0.2/24"), IPAddressRange("fd77::2/64")]
        profile.peers[0].allowedIPs = try [IPAddressRange("10.77.0.0/24"), IPAddressRange("fd77::/64")]
        profile.protection.ipv6Policy = policy
        profile.interface.dns = try [DNSServer("10.77.0.1"), DNSServer("fd77::1")]
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        let generation = try await h.start()
        await h.controller.consume(.handshakeCompleted(peer: profile.peers[0].publicKey, at: h.clock.wallNow), generation: generation)
        for _ in 0 ..< 12 {
            h.clock.advance(.seconds(5)); try await h.controller.tick()
        }
        let resource = try #require(h.journal.snapshot().resources.first)
        #expect(resource.addresses.contains { $0.isIPv6 })
        #expect(resource.routes.contains { $0.destination.contains(":") })
        #expect(await h.controller.status.protection == .protected)
        let status = await h.controller.status
        #expect(status.protectionNote == nil)
        #expect(resource.dns?.servers == ["10.77.0.1", "fd77::1"])
        #expect(await h.controller.selectedEndpoints[profile.peers[0].publicKey]?.host == "192.0.2.1")
    }

    @Test
    func `losing an IPv6 default preserves tunnel addresses routes and DNS`() async throws {
        let h = try ControllerHarness()
        var profile = h.profile
        profile.interface.addresses = try [IPAddressRange("10.77.0.2/24"), IPAddressRange("fd77::2/64")]
        profile.peers[0].allowedIPs = try [IPAddressRange("10.77.0.0/24"), IPAddressRange("fd77::/64")]
        profile.interface.dns = try [DNSServer("10.77.0.1"), DNSServer("fd77::1")]
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        let generation = try await h.start()
        await h.controller.consume(.handshakeCompleted(peer: profile.peers[0].publicKey, at: h.clock.wallNow), generation: generation)
        try await h.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: .init(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"], ipv6DefaultRouteAvailable: false,
        ), satisfied: true))
        let resource = try #require(h.journal.snapshot().resources.first)
        #expect(!h.trace.calls.contains("device.remove"))
        #expect(resource.addresses.contains { $0.isIPv6 })
        #expect(resource.routes.contains { $0.destination.contains(":") })
        #expect(resource.dns?.servers == ["10.77.0.1", "fd77::1"])
        #expect(await h.controller.status.protectionNote == nil)
        #expect(await h.controller.selectedEndpoints[profile.peers[0].publicKey]?.host == "192.0.2.1")
        try await h.controller.networkChanged(
            trigger: .configuration,
            underlay: .init(snapshot: ControllerHarness.underlay, satisfied: true),
        )
        let restored = try #require(h.journal.snapshot().resources.first)
        #expect(restored.addresses.contains { $0.isIPv6 })
        #expect(restored.dns?.servers == ["10.77.0.1", "fd77::1"])
        #expect(await h.controller.status.protectionNote == nil)
    }

    @Test(arguments: [false, true])
    func `only IPv6 endpoints fail closed without an underlay IPv6 default`(literal: Bool) async throws {
        let h = try ControllerHarness(underlay: .init(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"], ipv6DefaultRouteAvailable: false,
        ))
        var profile = h.profile
        if literal {
            profile.peers[0].endpoint = try Endpoint(validatingHost: "2001:db8::1", port: 51820)
        }
        await h.ports.setAnswers(["2001:db8::1"])
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        await #expect(throws: (any Error).self) { _ = try await h.start() }
        let status = await h.controller.status
        #expect(status.protection == .blocked)
        #expect(status.protectionNote == .ipv6Unavailable)
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(status)) as? [String: Any]
        #expect(encoded?["protectionNote"] as? Int == 1)
        #expect(!h.trace.calls.contains("engine.up"))
        try await h.controller.networkChanged(
            trigger: .configuration,
            underlay: .init(snapshot: ControllerHarness.underlay, satisfied: true),
        )
        h.clock.advance(.seconds(5)); try await h.controller.tick()
        #expect(await h.controller.status.protection == .protected)
        #expect(await h.controller.status.protectionNote == nil)
        #expect(await h.controller.selectedEndpoints[profile.peers[0].publicKey]?.host == "2001:db8::1")
    }

    @Test(arguments: [false, true])
    func `mixed endpoint families preserve reachable peers and report unavailable IPv6`(allUnavailable: Bool) async throws {
        let h = try ControllerHarness(underlay: .init(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"], ipv6DefaultRouteAvailable: false,
        ))
        var profile = h.profile
        profile.peers[0].endpoint = try Endpoint(validatingHost: "2001:db8::1", port: 51820)
        var reachable = profile.peers[0]
        reachable.publicKey = try ControllerHarness.makeProfile().interface.publicKey
        reachable.endpoint = try Endpoint(validatingHost: allUnavailable ? "2001:db8::2" : "192.0.2.2", port: 51820)
        reachable.allowedIPs = try [IPAddressRange("198.51.100.0/24")]
        profile.peers.append(reachable)
        _ = try await h.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        if allUnavailable {
            await #expect(throws: (any Error).self) { _ = try await h.start() }
            #expect(await h.controller.status.protection == .blocked)
        } else {
            _ = try await h.start()
            #expect(await h.controller.status.protection == .protected)
            #expect(await h.controller.selectedEndpoints[reachable.publicKey]?.host == "192.0.2.2")
            #expect(await h.controller.selectedEndpoints[profile.peers[0].publicKey] == nil)
            let engine = try #require(await h.ports.engine)
            #expect(await engine.endpointLineCount == 1)
        }
        #expect(await h.controller.status.protectionNote == .ipv6Unavailable)
    }

    @Test
    func `a cached IPv6 endpoint cannot override the IPv4 underlay preference`() async throws {
        let h = try ControllerHarness(underlay: .init(
            v4: 4,
            v6: 6,
            resolvers: ["192.0.2.53"],
            interfaceNames: ["underlay-test"],
            ipv6DefaultRouteAvailable: false,
        ))
        try await h.install()
        let endpoint = try #require(h.profile.peers[0].endpoint)
        try h.journal.mutate(generation: nil) { $0.lastGoodAddresses[endpoint.host] = ["2001:db8::1"] }
        _ = try await h.start()
        #expect(await h.controller.selectedEndpoints[h.profile.peers[0].publicKey]?.host == "192.0.2.1")
        #expect(await h.controller.status.protectionNote == nil)
    }

    @Test
    func `failed start publishes failed reasserting active without a user request`() async throws {
        let h = try ControllerHarness(); try await h.install()
        h.trace.fail(at: "engine.up")
        await #expect(throws: (any Error).self) { _ = try await h.start() }
        let updates = await h.controller.statusUpdates()
        let phases = Task { () -> [String] in
            var phases: [String] = []
            for await update in updates {
                switch update.phase {
                case .failed: phases.append("failed")
                case .reasserting: phases.append("reasserting")
                case .active: phases.append("active"); return phases
                default: break
                }
            }
            return phases
        }
        h.clock.advance(.seconds(5)); try await h.controller.tick()
        let seen = await phases.value
        #expect(seen.first == "failed")
        #expect(try #require(seen.firstIndex(of: "reasserting")) < #require(seen.firstIndex(of: "active")))
    }
}
