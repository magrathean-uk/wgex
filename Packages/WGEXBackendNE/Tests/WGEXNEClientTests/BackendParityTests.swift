// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
@testable import WGEXNEClient

@Suite(.timeLimit(.minutes(1)))
private struct SettingsStatusTests {
    @Test
    func `a tunnel already up at launch is reported against its own profile without any other call`() async throws {
        let (first, second) = try Profiles.pair()
        let system = ParitySystem(records: [Profiles.record(first, .disconnected), Profiles.record(second, .connected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        #expect(await updates.until { _ in true }?.phase == .idle)
        let launch = await updates.until { $0.phase != .idle }
        #expect(launch.map { isActive($0, second) } == true)
        #expect(await system.calls == ["load"])
        await client.shutdown()
    }

    @Test
    func `a Settings start of a profile the app never selected is reported against that profile`() async throws {
        let (first, second) = try Profiles.pair()
        let system = ParitySystem(records: [Profiles.record(first, .disconnected), Profiles.record(second, .disconnected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        await system.emit(second.id, .connecting)
        let preparing = await updates.until { $0.phase != .idle }
        guard case .preparing = preparing?.phase else { Issue.record("Missing preparing"); return }
        #expect(preparing?.activeProfileID == second.id)
        await system.emit(second.id, .connected)
        #expect(await updates.until { isActive($0, second) } != nil)
        // The live sample follows the tunnel Settings started.
        #expect(try await client.statistics() == ParitySystem.sample)
        #expect(await system.targets == [second.id])
        await system.emit(second.id, .disconnecting)
        await system.emit(second.id, .disconnected)
        let idle = await updates.until { $0.phase == .idle }
        #expect(idle?.activeProfileID == nil)
        #expect(updates.seen.allSatisfy { $0.activeProfileID != first.id })
        await client.shutdown()
    }

    @Test
    func `switching between two managers moves the report to the one coming up`() async throws {
        let (first, second) = try Profiles.pair()
        let system = ParitySystem(records: [Profiles.record(first, .disconnected), Profiles.record(second, .disconnected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        try await client.start(first.id, transport: nil)
        await system.emit(first.id, .connected)
        let firstActive = await updates.until { isActive($0, first) }
        // The app switches to the second profile; NE takes the first one down on its own. As the real adapter does, each
        // change repeats every manager's status, the first one's stale `connected` included.
        try await client.start(second.id, transport: nil)
        await system.emit(second.id, .connecting)
        await system.emit(first.id, .connected)
        await system.emit(first.id, .disconnecting)
        await system.emit(second.id, .connecting)
        await system.emit(first.id, .disconnected)
        await system.emit(second.id, .connected)
        let mark = updates.seen.count
        let secondActive = await updates.until { isActive($0, second) }
        #expect(updates.seen.dropFirst(mark).allSatisfy { $0.activeProfileID == second.id })
        #expect(try #require(generation(secondActive)) > #require(generation(firstActive)))
        // Settings switches back; the second manager's own disconnect never shows as idle.
        await system.emit(first.id, .connecting)
        await system.emit(second.id, .disconnecting)
        await system.emit(second.id, .disconnected)
        await system.emit(first.id, .connected)
        let back = updates.seen.count
        let firstAgain = await updates.until { isActive($0, first) }
        #expect(updates.seen.dropFirst(back).allSatisfy { $0.activeProfileID == first.id && $0.phase != .idle })
        #expect(try #require(generation(firstAgain)) > #require(generation(secondActive)))
        await client.shutdown()
    }

    @Test
    func `another VPN's manager never takes the report or the statistics`() async throws {
        let (first, second) = try Profiles.pair()
        let other = BuildIdentifiers(base: "com.example.OtherVPN", team: "TEAM")
        let foreign = VPNManagerRecord(
            id: second.id, configuration: ProtocolConfigurationBuilder.build(second, platform: .iOS, identifiers: other),
            name: second.name,
        )
        let system = ParitySystem(records: [Profiles.record(first, .connected), foreign])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        _ = await updates.until { isActive($0, first) }
        await system.emit(foreign.id, .connecting)
        await system.emit(foreign.id, .connected)
        await system.emit(first.id, .reasserting)
        let next = await updates.until { _ in true }
        #expect(next?.activeProfileID == first.id)
        guard case .reasserting = next?.phase else { Issue.record("A foreign manager took the report"); return }
        try await client.startStatistics(interval: 2)
        _ = try await client.statistics()
        #expect(await Set(system.targets) == [first.id])
        await client.shutdown()
    }

    @Test
    func `stopping a profile that is not up leaves the running tunnel reported`() async throws {
        let (first, second) = try Profiles.pair()
        let system = ParitySystem(records: [Profiles.record(first, .connected), Profiles.record(second, .disconnected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        _ = await updates.until { isActive($0, first) }
        try await client.stop(second.id)
        await system.emit(first.id, .reasserting)
        let next = await updates.until { _ in true }
        #expect(next?.activeProfileID == first.id)
        guard case .reasserting = next?.phase else { Issue.record("Lost the running tunnel"); return }
        await client.shutdown()
    }
}

/// Edits grouped by how a running tunnel takes them.
private enum Edit: String, CaseIterable, Sendable {
    case dns, mtu, peerEndpoint, keyReference, ipv6Policy, iosFlags, name, onDemand

    enum Effect { case reload, restart, saveOnly }

    var effect: Effect {
        switch self {
        case .dns, .mtu, .peerEndpoint, .keyReference, .ipv6Policy: .reload
        case .iosFlags: .restart
        case .name, .onDemand: .saveOnly
        }
    }

    func apply(to profile: inout TunnelProfile) throws {
        switch self {
        case .dns: profile.interface.dns = try [DNSServer("10.8.0.53")]
        case .mtu: profile.interface.mtu = 1380
        case .peerEndpoint: profile.peers[0].endpoint = try Endpoint("192.0.2.9:51820")
        case .keyReference: profile.secrets.privateKey = .keychain(persistentRef: Data([9, 9, 9]))
        case .ipv6Policy: profile.protection.ipv6Policy = .blockOutside
        case .iosFlags: profile.protection.ios.includeAllNetworks.toggle()
        case .name: profile.name = "Renamed"
        case .onDemand: profile.onDemand = .wifiOnly(exceptSSIDs: ["Home"])
        }
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ActiveEditTests {
    private func connected() throws -> (ParitySystem, NEManagerClient, TunnelProfile) {
        let profile = try GoldenFixture.profile()
        let system = ParitySystem(records: [Profiles.record(profile, .connected)])
        return (system, NEManagerClient(system: system, platform: .iOS), profile)
    }

    /// The preferences hold the edited profile and the tunnel runs what it reads of it.
    private func expectApplied(_ system: ParitySystem, _ profile: TunnelProfile) async {
        let stored = await system.stored.first
        #expect(stored?.configuration == ProtocolConfigurationBuilder.build(profile, platform: .iOS))
        #expect(stored?.name == profile.name)
        #expect(stored?.profileRevision == NEManagerClient.profileRevision(profile))
        #expect(await system.running[profile.id]?.profileRevision == NEManagerClient.profileRevision(profile))
    }

    @Test(arguments: Edit.allCases)
    func `an edit of the active tunnel is applied without a manual reconnect`(_ edit: Edit) async throws {
        let (system, client, original) = try connected()
        var profile = original
        try edit.apply(to: &profile)
        try await client.install(profile)
        let calls = await system.calls
        #expect(calls.prefix(3) == ["load", "save", "load"])
        switch edit.effect {
        case .reload:
            #expect(Array(calls.dropFirst(3)) == ["message"])
            #expect(await system.messages == [.reload(profileID: profile.id)])
        case .restart: #expect(Array(calls.dropFirst(3)) == ["stop", "start"])
        case .saveOnly: #expect(calls.count == 3)
        }
        await expectApplied(system, profile)
        if edit.effect != .saveOnly {
            #expect(await system.running[profile.id]?.configuration == ProtocolConfigurationBuilder.build(profile, platform: .iOS))
        }
        await client.shutdown()
    }

    /// Each class's own failure: the provider rejects a reload and ends the tunnel itself, a restart's stop times out with
    /// the old tunnel still up, a save-only edit cannot be saved. The tunnel runs the old profile or nothing, never a mix.
    @Test(arguments: Edit.allCases)
    func `a failed edit of the active tunnel leaves the old tunnel up or ends it cleanly`(_ edit: Edit) async throws {
        let (system, client, original) = try connected()
        let old = try #require(await system.stored.first)
        var profile = original
        try edit.apply(to: &profile)
        switch edit.effect {
        case .reload:
            await system.script(reload: .reply(.error(.engine(code: -6))))
            await #expect(throws: TunnelError.engine(code: -6)) { try await client.install(profile) }
            #expect(await Array(system.calls.dropFirst(3)) == ["message"])
            #expect(await system.running[profile.id] == nil)
            #expect(await system.stored.first?.profileRevision == NEManagerClient.profileRevision(profile))
        case .restart:
            await system.failStop(.timedOut)
            await #expect(throws: TunnelError.timedOut) { try await client.install(profile) }
            #expect(await Array(system.calls.dropFirst(3)) == ["stop"])
            #expect(await system.running[profile.id] == old)
        case .saveOnly:
            await system.failSaves(2)
            await #expect(throws: TunnelError.backendUnavailable) { try await client.install(profile) }
            #expect(await system.running[profile.id] == old)
            #expect(await system.stored == [old])
        }
        await client.shutdown()
    }

    @Test(arguments: Edit.allCases)
    func `an edit that cannot be saved never touches the running tunnel`(_ edit: Edit) async throws {
        let (system, client, original) = try connected()
        let old = try #require(await system.stored.first)
        await system.failSaves(2)
        var profile = original
        try edit.apply(to: &profile)
        await #expect(throws: TunnelError.backendUnavailable) { try await client.install(profile) }
        #expect(await system.calls == ["load", "save", "load", "save"])
        #expect(await system.running[profile.id] == old)
        #expect(await system.stored == [old])
        await client.shutdown()
    }

    @Test(arguments: [Edit.iosFlags, .dns])
    func `a retried edit whose stop failed is applied again, not skipped`(_ edit: Edit) async throws {
        let (system, client, original) = try connected()
        let old = try #require(await system.stored.first)
        var profile = original
        try edit.apply(to: &profile)
        if edit.effect == .reload {
            await system.script(reload: .undelivered)
        }
        await system.failStop(.timedOut)
        await #expect(throws: TunnelError.timedOut) { try await client.install(profile) }
        #expect(await system.running[profile.id] == old)
        await system.failStop(nil)
        await system.script(reload: .reply(.ok))
        let mark = await system.calls.count
        try await client.install(profile)
        #expect(await Array(system.calls.dropFirst(mark)) == (edit.effect == .reload ? ["message"] : ["stop", "start"]))
        await expectApplied(system, profile)
        await client.shutdown()
    }

    @Test
    func `a tunnel that comes back after a failed edit runs the saved profile and is not restarted again`() async throws {
        let (system, client, original) = try connected()
        var updates = Updates(client)
        _ = await updates.until { isActive($0, original) }
        var profile = original
        try Edit.iosFlags.apply(to: &profile)
        await system.failStop(.timedOut)
        await #expect(throws: TunnelError.timedOut) { try await client.install(profile) }
        // The old tunnel drops by itself and on-demand brings it back with the saved profile.
        await system.emit(profile.id, .disconnected)
        _ = await updates.until { $0.phase == .idle }
        await system.reconnect(profile.id)
        _ = await updates.until { isActive($0, profile) }
        await system.failStop(nil)
        let mark = await system.calls.count
        try await client.install(profile)
        #expect(await system.calls.count == mark)
        await expectApplied(system, profile)
        await client.shutdown()
    }

    @Test
    func `an edit of a tunnel that is not up is only saved`() async throws {
        var profile = try GoldenFixture.profile()
        let system = ParitySystem(records: [Profiles.record(profile, .disconnected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        try Edit.dns.apply(to: &profile)
        try await client.install(profile)
        #expect(await system.calls == ["load", "save", "load"])
        #expect(await system.running.isEmpty)
        await client.shutdown()
    }

    @Test(arguments: [ReloadOutcome.undelivered, .unreadable, .reply(.status(.idle))])
    func `a reload that cannot be delivered or read falls back to stop and start`(_ outcome: ReloadOutcome) async throws {
        let (system, client, original) = try connected()
        await system.script(reload: outcome)
        var profile = original
        try Edit.peerEndpoint.apply(to: &profile)
        try await client.install(profile)
        #expect(await Array(system.calls.suffix(3)) == ["message", "stop", "start"])
        await expectApplied(system, profile)
        await client.shutdown()
    }

    @Test
    func `a fallback whose start fails leaves the tunnel stopped and reports it`() async throws {
        let (system, client, original) = try connected()
        await system.script(reload: .undelivered)
        await system.failStart(.secretsUnavailable)
        var profile = original
        try Edit.keyReference.apply(to: &profile)
        await #expect(throws: NEManagerClient.reconnectFailure) { try await client.install(profile) }
        #expect(await Array(system.calls.suffix(3)) == ["message", "stop", "start"])
        #expect(await system.running[profile.id] == nil)
        await client.shutdown()
    }

    @Test
    func `the profile revision ignores fields a running tunnel never reads and is stable`() throws {
        let profile = try GoldenFixture.profile()
        var renamed = profile
        try Edit.name.apply(to: &renamed)
        var moved = profile
        try Edit.peerEndpoint.apply(to: &moved)
        #expect(NEManagerClient.profileRevision(renamed) == NEManagerClient.profileRevision(profile))
        #expect(NEManagerClient.profileRevision(moved) != NEManagerClient.profileRevision(profile))
        let revision = NEManagerClient.profileRevision(profile)
        #expect(revision.count == 64 && revision.allSatisfy(\.isHexDigit))
    }
}

/// How a start gives up on its subscribe request.
private enum Withdrawal: CaseIterable, Sendable {
    case cancellation, deadline
}

/// The first deadline passes once the subscribe request is held; every later one never passes by itself.
private actor FirstDeadline {
    private var passed = false

    func claim() -> Bool {
        defer { passed = true }
        return !passed
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct LiveStatisticsTests {
    @Test
    func `the caller starts, samples and stops the statistics subscription of the active tunnel`() async throws {
        let profile = try GoldenFixture.profile()
        let system = ParitySystem(records: [Profiles.record(profile, .connected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        _ = await updates.until { isActive($0, profile) }
        try await client.startStatistics(interval: 2)
        #expect(await system.subscribed == [profile.id])
        let sample = try await client.statistics()
        #expect(sample.peers.map(\.rxBytes) == [1200])
        #expect(sample.peers.map(\.txBytes) == [3400])
        #expect(sample.peers.map(\.lastHandshake) == [Date(timeIntervalSince1970: 40)])
        await client.stopStatistics()
        await client.stopStatistics()
        #expect(await system.messages == [.subscribeStats(interval: 2), .statistics, .unsubscribeStats])
        #expect(await Set(system.targets) == [profile.id])
        #expect(await system.subscribed.isEmpty)
        await client.shutdown()
    }

    private func active(
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        system: ParitySystem,
    ) async throws -> NEManagerClient {
        let profile = try #require(await system.stored.first)
        let client = NEManagerClient(system: system, platform: .iOS, sleep: sleep)
        var updates = Updates(client)
        _ = await updates.until { $0.activeProfileID == profile.configuration.profileID }
        return client
    }

    @Test
    func `a stop that arrives while the subscription awaits its reply still ends it`() async throws {
        let system = try ParitySystem(records: [Profiles.record(GoldenFixture.profile(), .connected)])
        let client = try await active(system: system)
        await system.holdSubscribeReplies()
        let start = Task { try await client.startStatistics(interval: 5) }
        await system.waitUntilSubscribeHeld()
        let stop = Task { await client.stopStatistics() }
        var spins = 0
        while await client.pendingStatisticsOperationCount == 0, spins < 10000 {
            spins += 1; await Task.yield()
        }
        #expect(await client.pendingStatisticsOperationCount == 1)
        await system.releaseHeld()
        try await start.value
        await stop.value
        #expect(await system.messages == [.subscribeStats(interval: 5), .unsubscribeStats])
        #expect(await system.subscribed.isEmpty)
        await client.shutdown()
    }

    @Test
    func `a start cancelled after the provider took the request withdraws it`() async throws {
        let system = try ParitySystem(records: [Profiles.record(GoldenFixture.profile(), .connected)])
        let client = try await active(system: system)
        await system.holdSubscribeReplies()
        let start = Task { try await client.startStatistics(interval: 5) }
        await system.waitUntilSubscribeHeld()
        start.cancel()
        await #expect(throws: TunnelError.cancelled) { try await start.value }
        // The withdrawal runs behind the caller with the statistics gate held; a stop waits for it and adds nothing.
        await client.stopStatistics()
        #expect(await system.subscribed.isEmpty)
        #expect(await system.messages == [.subscribeStats(interval: 5), .unsubscribeStats])
        await system.releaseHeld()
        await client.stopStatistics()
        #expect(await system.messages.count == 2)
        await client.shutdown()
    }

    @Test
    func `a subscription whose reply misses the deadline is withdrawn`() async throws {
        let system = try ParitySystem(records: [Profiles.record(GoldenFixture.profile(), .connected)])
        let deadline = FirstDeadline()
        let client = try await active(sleep: { duration in
            if await deadline.claim() {
                await system.waitUntilSubscribeHeld()
            } else {
                try await Task.sleep(for: duration)
            }
        }, system: system)
        await system.holdSubscribeReplies()
        await #expect(throws: TunnelError.timedOut) { try await client.startStatistics(interval: 5) }
        await client.stopStatistics()
        #expect(await system.subscribed.isEmpty)
        #expect(await system.messages == [.subscribeStats(interval: 5), .unsubscribeStats])
        await system.releaseHeld()
        await client.stopStatistics()
        #expect(await system.messages.count == 2)
        await client.shutdown()
    }

    /// The request is held before the provider takes it while the start is withdrawn by cancellation or the deadline.
    /// A system that checks cancellation drops it, so the withdrawal completes before the release; one that does not
    /// delivers it on release, and the withdrawal's unsubscribe follows it instead of overtaking it.
    @Test(arguments: Withdrawal.allCases, [true, false])
    func `a subscribe still on its way when the start is withdrawn never outlives the withdrawal`(
        withdrawal: Withdrawal, checksCancellation: Bool,
    ) async throws {
        let system = try ParitySystem(records: [Profiles.record(GoldenFixture.profile(), .connected)])
        let deadline = FirstDeadline()
        let client = try await active(sleep: { duration in
            if withdrawal == .deadline, await deadline.claim() {
                await system.waitUntilSubscribeHeld()
            } else {
                try await Task.sleep(for: duration)
            }
        }, system: system)
        await system.holdSubscribeDelivery(checksCancellation: checksCancellation)
        let start = Task { try await client.startStatistics(interval: 5) }
        switch withdrawal {
        case .cancellation:
            await system.waitUntilSubscribeHeld()
            start.cancel()
            await #expect(throws: TunnelError.cancelled) { try await start.value }
        case .deadline:
            await #expect(throws: TunnelError.timedOut) { try await start.value }
        }
        if checksCancellation {
            // The cancelled send ended undelivered, so the withdrawal completes before the release.
            await client.stopStatistics()
            #expect(await system.messages == [.unsubscribeStats])
            await system.releaseHeld()
            await client.stopStatistics()
            #expect(await system.messages == [.unsubscribeStats])
        } else {
            // The caller is free, but nothing has overtaken the request still on its way, and a stop waits behind it.
            #expect(await system.messages.isEmpty)
            let stop = Task { await client.stopStatistics() }
            var spins = 0
            while await client.pendingStatisticsOperationCount == 0, spins < 10000 {
                spins += 1; await Task.yield()
            }
            #expect(await client.pendingStatisticsOperationCount == 1)
            #expect(await system.messages.isEmpty)
            await system.releaseHeld()
            await stop.value
            #expect(await system.messages == [.subscribeStats(interval: 5), .unsubscribeStats])
        }
        #expect(await system.subscribed.isEmpty)
        await client.stopStatistics()
        #expect(await system.subscribed.isEmpty)
        await client.shutdown()
    }

    @Test
    func `a rejected interval or no active tunnel starts nothing`() async throws {
        let idle = ParitySystem()
        let idleClient = NEManagerClient(system: idle, platform: .iOS)
        await #expect(throws: TunnelError.backendUnavailable) { try await idleClient.startStatistics(interval: 2) }
        await idleClient.stopStatistics()
        #expect(await idle.messages.isEmpty)
        let profile = try GoldenFixture.profile()
        let system = ParitySystem(records: [Profiles.record(profile, .connected)])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = Updates(client)
        _ = await updates.until { isActive($0, profile) }
        await #expect(throws: TunnelError.invalidConfiguration(.statisticsInterval)) { try await client.startStatistics(interval: 1) }
        await client.stopStatistics()
        #expect(await system.messages == [.subscribeStats(interval: 1)])
        await client.shutdown(); await idleClient.shutdown()
    }
}
