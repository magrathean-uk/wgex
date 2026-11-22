// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXTesting

private struct FakeTunnelBackendTests {
    @Test
    func `default start script ends active and protected`() async throws {
        let backend = FakeTunnelBackend()
        let profile = TunnelProfile(name: "Lab")
        try await backend.install(profile)
        var updates = backend.statusUpdates().makeAsyncIterator()
        #expect(await updates.next()?.phase == .idle)
        try await backend.start(profile.id, transport: nil)
        #expect(await updates.next()?.phase == .preparing(Generation(rawValue: 1)))
        #expect(await updates.next()?.phase == .configuring(Generation(rawValue: 1)))
        let active = await updates.next()
        #expect(active?.phase == .active(Generation(rawValue: 1)))
        #expect(active?.protection == .protected)
        try await backend.stop(profile.id)
        #expect(backend.currentStatus.phase == .idle)
        #expect(backend.calls == [.install(profile.id), .start(profile.id, transport: nil), .stop(profile.id)])
    }

    @Test
    func `scripted delays follow the fake clock`() async throws {
        let clock = FakeClock()
        let backend = FakeTunnelBackend(clock: clock)
        let profile = TunnelProfile(name: "Slow")
        try await backend.install(profile)
        backend.scriptStart([
            .init(phase: .preparing(.initial), protection: .blocked, delay: .seconds(3)),
            .init(phase: .active(.initial), protection: .protected, delay: .seconds(2)),
        ])
        let start = Task { try await backend.start(profile.id, transport: nil) }
        await clock.waitForSleepers(1)
        #expect(backend.currentStatus.phase == .idle)
        clock.advance(by: .seconds(3))
        await clock.waitForSleepers(1)
        #expect(backend.currentStatus.phase == .preparing(.initial))
        clock.advance(by: .seconds(2))
        try await start.value
        #expect(backend.currentStatus.phase == .active(.initial))
    }

    @Test
    func `faults and unknown profiles fail`() async throws {
        let backend = FakeTunnelBackend()
        await #expect(throws: TunnelError.profileNotFound(UUID(uuidString: "00000000-0000-0000-0000-000000000001") ?? UUID())) {
            try await backend.start(UUID(uuidString: "00000000-0000-0000-0000-000000000001") ?? UUID(), transport: nil)
        }
        backend.faults.arm("install", error: TunnelError.secretsUnavailable)
        await #expect(throws: TunnelError.secretsUnavailable) { try await backend.install(TunnelProfile(name: "X")) }
        #expect(backend.installedProfiles.isEmpty)
        let stats = try await backend.statistics()
        #expect(stats.peers.isEmpty)
    }
}
