// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct ControllerEndpointTests {
    @Test
    func `candidates rotate after two rekey timeouts without re-resolving healthy endpoints`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        #expect(await harness.controller.selectedEndpoints.values.first?.host == "2001:db8::1")
        harness.clock.advance(.seconds(9)); try await harness.controller.tick()
        #expect(!harness.trace.calls.contains("engine.endpoints"))
        harness.clock.advance(.seconds(1)); try await harness.controller.tick()
        #expect(await harness.controller.selectedEndpoints.values.first?.host == "192.0.2.1")
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count == 1)
        #expect(harness.trace.calls.filter { $0 == "engine.endpoints" }.count == 1)
        #expect(await harness.controller.status.protection == .blocked)
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: epoch)
        #expect(await harness.controller.status.phase == .active(epoch))
        #expect(await harness.ports.policy == .connected(interfaceName: "utun-test", endpoints: ["192.0.2.1:51820", "[2001:db8::1]:51820"]))
        harness.clock.advance(.seconds(500)); try await harness.controller.tick()
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count == 1)
    }

    @Test
    func `all failed candidates back off five to sixty seconds and re-resolve through the underlay`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.setAnswers(["192.0.2.1"])
        _ = try await harness.start()
        for expected in [5, 10, 20, 40, 60, 60] {
            harness.clock.advance(.seconds(10)); try await harness.controller.tick()
            for _ in 0 ..< 2000 where !harness.clock.pendingSleeps.contains(.seconds(expected)) {
                await Task.yield()
            }
            #expect(harness.clock.pendingSleeps.contains(.seconds(expected)))
            let before = harness.trace.calls.filter { $0 == "resolver.resolve" }.count
            harness.clock.advance(.seconds(expected))
            // Completion notification is the controller status event, with no real-time sleeps.
            while harness.trace.calls.filter({ $0 == "resolver.resolve" }).count == before {
                await Task.yield()
            }
            while await harness.controller.operation != nil {
                await Task.yield()
            }
        }
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count == 7)
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
    }

    @Test
    func `successful handshake cancels a pending all candidates retry`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        await harness.ports.setAnswers(["192.0.2.1"])
        let epoch = try await harness.start()
        harness.clock.advance(.seconds(10)); try await harness.controller.tick()
        for _ in 0 ..< 2000 where !harness.clock.pendingSleeps.contains(.seconds(5)) {
            await Task.yield()
        }
        #expect(harness.clock.pendingSleeps.contains(.seconds(5)))
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: epoch)
        harness.clock.advance(.seconds(600)); try await harness.controller.tick()
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count == 1)
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `health uses engine events and bounds recent events at thirty two`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        await harness.controller.consume(.txWithoutRx(since: harness.clock.wallNow.addingTimeInterval(-15)), generation: epoch)
        #expect(await harness.controller.status.health.level == .degraded(reason: "txWithoutRx"))
        #expect(harness.trace.calls.contains("engine.handshake"))
        harness.clock.advance(.seconds(15)); try await harness.controller.tick()
        #expect(await harness.controller.status.health.level == .unresponsive)
        let peer = try #require(harness.profile.peers.first?.publicKey)
        for _ in 0 ..<
            40
        {
            await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: epoch)
        }
        #expect(await harness.controller.status.health.level == .healthy)
        #expect(await harness.controller.status.recentEvents.count == 32)
        await harness.controller.consume(.txWithoutRx(since: harness.clock.wallNow), generation: epoch.next())
        #expect(await harness.controller.status.health.level == .healthy)
        await #expect(throws: DaemonFailure.controllerOperationFailed) {
            try await harness.controller.pathChanged(ControllerHarness.underlay, satisfied: false)
        }
        #expect(await harness.controller.status.health.level == .offline)
    }

    @Test
    func `path change re-resolves but unchanged endpoints do not force a new handshake`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        let peer = try #require(harness.profile.peers.first?.publicKey)
        await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: epoch)
        try await harness.controller.pathChanged(ControllerHarness.underlay, satisfied: true)
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count == 2)
        #expect(harness.trace.calls.contains("engine.bump"))
        #expect(!harness.trace.calls.contains("engine.handshake"))
        #expect(!harness.trace.calls.contains("engine.endpoints"))
    }
}
