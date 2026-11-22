// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// M1-18: the guest run 6 timeline (rerun 29 Oct 2026) replayed on the XNU route model. Every connect reached
/// active/protected, then the kernel moved ifi_lastchange with no change by the daemon: en0 about 0.2 s later and utun4
/// about 5 s later, by whole seconds, index unchanged. The stamp-based fence refused on each ("route interface drift",
/// "tunnel identity drift", later "device interface drift"). These tests use only API present at ff001e5, so they also
/// run against that tree for the red capture.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6StampTimelineTests {
    private static let underlay = UnderlaySnapshot(
        v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"], interfaceV4Name: "en0", ipv4Router: "192.0.2.254",
    )

    @Test
    func `M1-18 the guest timeline stays protected while the kernel moves en0 and utun stamps on its own`() async throws {
        let stack = try await ModelStack()
        let generation = try await stack.start()
        let peer = try #require(stack.host.profile.peers.first?.publicKey)
        await stack.controller.consume(.handshakeCompleted(peer: peer, at: stack.host.clock.wallNow), generation: generation)
        #expect(await stack.controller.status.protection == .protected)
        // +0.2 s: en0's stamp moves; the underlay change reaches the daemon as a path change (reinstalls the canary).
        stack.host.clock.advance(.milliseconds(200))
        stack.model.touch("en0")
        try await stack.controller.pathChanged(Self.underlay, satisfied: true)
        stack.host.clock.advance(.seconds(5))
        try await stack.controller.tick()
        #expect(await stack.controller.status.phase == .active(generation))
        #expect(await stack.controller.status.protection == .protected)
        // About +5 s: utun's stamp moves; the periodic verification runs on the next tick.
        stack.model.touch("utun9")
        stack.host.clock.advance(.seconds(5))
        try await stack.controller.tick()
        #expect(await stack.controller.status.phase == .active(generation))
        #expect(await stack.controller.status.protection == .protected)
        // Later ticks with both stamps moved again: the recovery reconfigure and verification still hold.
        stack.model.touch("utun9"); stack.model.touch("en0")
        let recorded = try #require(stack.journal.snapshot().resources.first?.identity)
        try await stack.controller.configureChangedUnderlay(stack.host.profile, identity: recorded)
        stack.host.clock.advance(.seconds(5))
        try await stack.controller.tick()
        #expect(await stack.controller.status.protection == .protected)
        #expect(stack.journal.snapshot().resources.first?.identity == recorded)
        #expect(stack.model.canaries.count == 1)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `M1-18 crash replay after both stamps moved removes the journalled canary and keeps the record consistent`() async throws {
        let stack = try await ModelStack()
        _ = try await stack.start()
        #expect(stack.model.canaries.count == 1)
        try await stack.journal.mutate(generation: stack.controller.currentGeneration) { $0.intent = nil }
        await stack.controller.cancelBackgroundWork()
        stack.model.touch("en0"); stack.model.touch("utun9")
        let replacement = try stack.replacement()
        try await replacement.reconcileAtStartup()
        #expect(stack.model.canaries.isEmpty)
        #expect(try DaemonJournal(directory: StateDirectory(root: stack.host.root)).snapshot().resources.isEmpty)
        await replacement.cancelBackgroundWork()
    }
}
