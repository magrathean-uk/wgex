// SPDX-License-Identifier: Apache-2.0 AND MIT

// Adapted from firezone swift/apple FirezoneKit/Tests/FirezoneKitTests/VPNConfigurationManagerTests.swift at
// 229ac31b37b5fbde2961e7f87df8181abd7fd46f, Apache-2.0
// Copyright Firezone, Inc. Licensed under Apache-2.0; see Vendor/firezone/NOTICE and LICENSE.
import Foundation
import Testing
import WGEXCore
@testable import WGEXNEClient

private actor FakeVPNManagerSystem: VPNManagerSystem {
    private(set) var stored: [VPNManagerRecord] = []
    private(set) var calls: [String] = []
    private(set) var saved: [VPNManagerRecord] = []
    private var failures = 0
    private var held = false
    private var blocked: CheckedContinuation<Void, Never>?
    private let events: AsyncStream<VPNStatusEvent>
    private let continuation: AsyncStream<VPNStatusEvent>.Continuation

    init(records: [VPNManagerRecord] = [], failures: Int = 0) {
        stored = records; self.failures = failures
        (events, continuation) = AsyncStream.makeStream()
    }

    func holdNextSave() {
        held = true
    }

    func releaseSave() {
        blocked?.resume(); blocked = nil
    }

    func isBlocked() -> Bool {
        blocked != nil
    }

    func loadAll() -> [VPNManagerRecord] {
        calls.append("load"); return stored
    }

    func save(_ record: VPNManagerRecord) async throws {
        calls.append("save"); saved.append(record)
        if held {
            held = false; await withCheckedContinuation { blocked = $0 }
        }
        if failures > 0 {
            failures -= 1; throw TunnelError.backendUnavailable
        }
        stored.removeAll { $0.configuration.profileID == record.configuration.profileID }; stored.append(record)
    }

    func remove(_ id: UUID) {
        calls.append("remove"); stored.removeAll { $0.id == id }
    }

    func start(_: UUID, transport _: UUID?) {
        calls.append("start")
    }

    func stop(_: UUID) {
        calls.append("stop")
    }

    func startConfirmed(_: UUID, revision _: String?) {
        calls.append("start")
    }

    func statusEvents() -> AsyncStream<VPNStatusEvent> {
        events
    }

    func emit(_ event: VPNStatusEvent) {
        continuation.yield(event)
    }

    func sendProviderMessage(_: UUID, data: Data) throws -> Data {
        #expect(try ProviderCodec.decode(ProviderMessage.self, from: data) == .statistics)
        return try ProviderCodec.encode(ProviderReply.statistics(TunnelStatistics(
            generation: 7, sampledAt: Date(timeIntervalSince1970: 0), interfaceName: "utun-test", listenPort: nil, peers: [],
        )))
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ManagerTests {
    @Test
    func `foreign provider identities are ignored`() async throws {
        let profile = try GoldenFixture.profile()
        let foreign = VPNManagerRecord(
            configuration: ProtocolConfigurationBuilder.build(
                profile,
                platform: .iOS,
                identifiers: BuildIdentifiers(base: "foreign", team: "T"),
            ),
            name: "Foreign",
        )
        let system = FakeVPNManagerSystem(records: [foreign])
        let client = NEManagerClient(system: system, platform: .iOS)
        await #expect(throws: TunnelError.profileNotFound(profile.id)) { try await client.start(profile.id, transport: nil) }
        #expect(await system.calls == ["load"])
        await client.shutdown()
    }

    @Test
    func `load precedes save and a failed save reloads then retries once`() async throws {
        let system = FakeVPNManagerSystem(failures: 1)
        let client = NEManagerClient(system: system, platform: .iOS)
        try await client.install(GoldenFixture.profile())
        #expect(await system.calls == ["load", "save", "load", "save", "load"])
        #expect(await !client.failedWrite)
        await client.shutdown()
    }

    @Test
    func `two failures latch and the next equivalent request still writes`() async throws {
        let system = FakeVPNManagerSystem(failures: 2)
        let client = NEManagerClient(system: system, platform: .iOS)
        let profile = try GoldenFixture.profile()
        await #expect(throws: TunnelError.backendUnavailable) { try await client.install(profile) }
        #expect(await client.failedWrite)
        try await client.install(profile)
        #expect(await system.calls == ["load", "save", "load", "save", "load", "save", "load"])
        #expect(await !client.failedWrite)
        await client.shutdown()
    }

    @Test
    func `equivalent writes skip and manual stop disarms before stop then start rearms`() async throws {
        let system = FakeVPNManagerSystem()
        let client = NEManagerClient(system: system, platform: .iOS)
        let profile = try GoldenFixture.profile()
        try await client.install(profile)
        try await client.install(profile)
        #expect(await system.saved.count == 1)
        try await client.start(profile.id, transport: nil)
        try await client.stop(profile.id)
        #expect(await system.saved.last?.isOnDemandEnabled == false)
        #expect(await system.calls.suffix(3) == ["save", "load", "stop"])
        let savesAfterStop = await system.saved.count
        try await client.install(profile)
        #expect(await system.saved.count == savesAfterStop)
        #expect(await system.stored.last?.isOnDemandEnabled == false)
        try await client.start(profile.id, transport: nil)
        #expect(await system.saved.last?.isOnDemandEnabled == true)
        #expect(try await client.statistics().generation == 7)
        try await client.remove(profile.id, purgeSecrets: false)
        #expect(await system.stored.isEmpty)
        await client.shutdown()
    }

    @Test
    func `following the on-demand rules arms and disarms the manager without starting or stopping its tunnel`() async throws {
        let system = FakeVPNManagerSystem()
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = client.statusUpdates().makeAsyncIterator()
        #expect(await updates.next()?.phase == .idle)
        var profile = try GoldenFixture.profile()
        profile.onDemand = .always(exceptSSIDs: [])
        try await client.install(profile)
        // An install alone keeps a new manager disarmed; following its rules arms it.
        #expect(await system.stored.last?.isOnDemandEnabled == false)
        try await client.followOnDemandRules(profile.id)
        #expect(await system.stored.last?.isOnDemandEnabled == true)
        let id = try #require(await system.stored.first?.id)
        await system.emit(VPNStatusEvent(managerID: id, sequence: 1, status: .connected))
        guard case .active = await updates.next()?.phase else { Issue.record("Missing active"); return }
        // On-demand off on the running tunnel: saved and disarmed, and the tunnel is neither reloaded nor restarted.
        profile.onDemand = .off
        try await client.install(profile)
        try await client.followOnDemandRules(profile.id)
        #expect(await system.stored.last?.isOnDemandEnabled == false)
        #expect(await system.stored.last?.configuration.onDemandRules.isEmpty == true)
        profile.onDemand = .wifiOnly(exceptSSIDs: ["Cafe"])
        try await client.install(profile)
        try await client.followOnDemandRules(profile.id)
        #expect(await system.stored.last?.isOnDemandEnabled == true)
        let calls = await system.calls
        #expect(!calls.contains("start") && !calls.contains("stop"))
        let missing = UUID()
        await #expect(throws: TunnelError.profileNotFound(missing)) { try await client.followOnDemandRules(missing) }
        await client.shutdown()
    }

    @Test
    func `rapid supersession never starts after the newer manual stop`() async throws {
        let system = FakeVPNManagerSystem()
        let client = NEManagerClient(system: system, platform: .iOS)
        let profile = try GoldenFixture.profile()
        try await client.install(profile)
        try await client.stop(profile.id)
        await system.holdNextSave()
        let start = Task { try await client.start(profile.id, transport: nil) }
        while await !system.isBlocked() {
            await Task.yield()
        }
        let stop = Task { try await client.stop(profile.id) }
        // The queued stop increments the public intent before waiting on the FIFO gate.
        while await client.pendingOperationCount == 0 {
            await Task.yield()
        }
        await system.releaseSave()
        await #expect(throws: TunnelError.cancelled) { try await start.value }
        try await stop.value
        #expect(await !system.calls.contains("start"))
        #expect(await system.calls.last == "stop")
        await client.shutdown()
    }

    @Test
    func `status stream preserves sequence and rejects stale foreign events`() async throws {
        let system = FakeVPNManagerSystem()
        let client = NEManagerClient(system: system, platform: .iOS)
        var profile = try GoldenFixture.profile()
        var updates = client.statusUpdates().makeAsyncIterator()
        #expect(await updates.next()?.phase == .idle)
        try await client.install(profile)
        try await client.start(profile.id, transport: nil)
        guard case .preparing = await updates.next()?.phase else { Issue.record("Missing preparing"); return }
        let id = try #require(await system.stored.first?.id)
        await system.emit(VPNStatusEvent(managerID: id, sequence: 2, status: .connected))
        guard case .active = await updates.next()?.phase else { Issue.record("Missing active"); return }
        profile.protection.ios.includeAllNetworks.toggle()
        try await client.install(profile)
        #expect(await system.calls.suffix(4) == ["save", "load", "stop", "start"])
        await system.emit(VPNStatusEvent(managerID: id, sequence: 1, status: .disconnected))
        await system.emit(VPNStatusEvent(managerID: UUID(), sequence: 3, status: .invalid))
        await system.emit(VPNStatusEvent(managerID: id, sequence: 4, status: .reasserting))
        guard case .reasserting = await updates.next()?.phase else { Issue.record("Out of order status"); return }
        await client.shutdown()
    }

    @Test
    func `changed protection flags save then restart a connected manager`() async throws {
        var profile = try GoldenFixture.profile()
        let old = VPNManagerRecord(
            id: profile.id, configuration: ProtocolConfigurationBuilder.build(profile, platform: .iOS), name: profile.name,
            isOnDemandEnabled: true, status: .connected,
        )
        let system = FakeVPNManagerSystem(records: [old])
        let client = NEManagerClient(system: system, platform: .iOS)
        profile.protection.ios.includeAllNetworks.toggle()
        try await client.install(profile)
        #expect(await system.calls == ["load", "save", "load", "stop", "start"])
        await client.shutdown()
    }

    @Test
    func `loading an already connected manager publishes its current status`() async throws {
        let profile = try GoldenFixture.profile()
        let record = VPNManagerRecord(
            id: profile.id, configuration: ProtocolConfigurationBuilder.build(profile, platform: .iOS), name: profile.name,
            isOnDemandEnabled: true, status: .connected, profileRevision: NEManagerClient.profileRevision(profile),
        )
        let system = FakeVPNManagerSystem(records: [record])
        let client = NEManagerClient(system: system, platform: .iOS)
        var updates = client.statusUpdates().makeAsyncIterator()
        #expect(await updates.next()?.phase == .idle)
        try await client.install(profile)
        #expect(await updates.next()?.phase == .active(.initial))
        #expect(await system.calls == ["load"])
        await client.shutdown()
    }

    @Test(arguments: VPNStatus.allCases)
    func `every NE status maps without unsupported protection claims`(_ status: VPNStatus) {
        let mapped = NETunnelBackend.status(status)
        switch status {
        case .invalid: #expect(mapped.phase == .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false))
        case .disconnected: #expect(mapped.phase == .idle)
        case .connecting: #expect(mapped.phase == .preparing(.initial))
        case .connected: #expect(mapped.phase == .active(.initial))
        case .reasserting: #expect(mapped.phase == .reasserting(.initial, reason: .pathChanged))
        case .disconnecting: #expect(mapped.phase == .stopping(.initial, reason: .userRequested))
        }
        #expect(mapped.protection != .blocked)
    }

    @Test
    func `platform capabilities exclude unproved kill switch and Mac operations`() {
        for platform in [ProfilePlatform.iOS, .tvOS] {
            let client = NEManagerClient(system: FakeVPNManagerSystem(), platform: platform)
            #expect(client.capabilities == [.onDemand, .allowLAN, .transportSwitching])
        }
    }
}
