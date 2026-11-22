// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

@Suite(.timeLimit(.minutes(1)))
private struct RuntimeCostTests {
    @Test
    func `owner index is read once and invalidates when a profile is removed`() async throws {
        let harness = try ControllerHarness(), repository = CountingOwnerRepository()
        let registry = ProfileRegistry(repository: repository, secrets: harness.store, bundles: harness.store)
        _ = try await registry.installProfile(harness.profile, expectedRevision: nil, connectionUID: 501)
        #expect(try await registry.profileIDs(ownedBy: 501) == [harness.profile.id])
        #expect(try await registry.profileIDs(ownedBy: 502).isEmpty)
        #expect(repository.reads == 1)
        try await registry.removeProfile(harness.profile.id, purgeSecrets: false, connectionUID: 501)
        #expect(try await registry.profileIDs(ownedBy: 501).isEmpty)
        #expect(repository.reads == 2)
    }

    @Test
    func `a transient underlay read failure is queued and recovered by the next retry`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let underlay = FakeUnderlayMonitor(), reader = RetryingUnderlayRead()
        let monitoring = DaemonNetworkMonitoring(
            controller: harness.controller, routes: FakeRouteMonitor(), underlay: underlay,
            power: FakePowerMonitor(), login: FakeLoginSessionMonitor(), ownPID: 123, clock: harness.clock,
            readUnderlay: { try await reader.read() },
        )
        try await monitoring.start()
        underlay.send(.init(snapshot: ControllerHarness.underlay, satisfied: true))
        for _ in 0 ..< 10000 where !harness.clock.pendingSleeps.contains(.milliseconds(500)) {
            await Task.yield()
        }
        harness.clock.advance(.milliseconds(500))
        for _ in 0 ..< 10000 where await harness.controller.status.protection != .unknown {
            await Task.yield()
        }
        #expect(await harness.controller.status.protection == .unknown)
        harness.clock.advance(.seconds(5)); await monitoring.retryPending()
        #expect(await harness.controller.status.protection == .protected)
        #expect(await reader.reads == 2)
        await monitoring.stop()
    }

    @Test
    func `unchanged controller ticks produce no records in the production diagnostics adapter`() async throws {
        let diagnostics = DaemonDiagnosticsAdapter(), h = try ControllerHarness()
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        try await h.controller.setGlobalSettings(settings)
        let initial = await h.controller.status
        #expect(await diagnostics.record(.init(event: .status(initial), profileID: h.profile.id, ownerUID: 501)) != nil)
        let baseline = try await diagnostics.logs(since: nil, limit: 512, visibleProfileIDs: [h.profile.id]).count
        let reads = await h.ports.verificationReads
        for _ in 0 ..< 100 {
            h.clock.advance(.seconds(5)); try await h.controller.tick()
            let status = await h.controller.status
            #expect(status.hasSameState(as: initial))
            #expect(await diagnostics.record(.init(event: .status(status), profileID: h.profile.id, ownerUID: 501)) == nil)
        }
        #expect(try await diagnostics.logs(since: nil, limit: 512, visibleProfileIDs: [h.profile.id]).count == baseline)
        #expect(await h.ports.verificationReads - reads == 100)
        await h.controller.monitoringFailed()
        let changed = await h.controller.status
        #expect(await diagnostics.record(.init(event: .status(changed), profileID: h.profile.id, ownerUID: 501)) != nil)
        #expect(await diagnostics.record(.init(event: .status(changed), profileID: h.profile.id, ownerUID: 501)) == nil)
        #expect(try await diagnostics.logs(since: nil, limit: 512, visibleProfileIDs: [h.profile.id]).count == baseline + 1)
    }

    @Test
    func `tunnel ranges use a constant content addressed table`() throws {
        let ranges = try (0 ..< 1000).map { try IPAddressRange("10.\($0 / 256).\($0 % 256).0/24") }
        let text = try PacketFilterRenderer.render(phase: .error, modifiers: .init(), context: .init(
            underlay: PFInterface("en0"), tunnelRanges: ranges, consoleUID: 501,
        ))
        #expect(text.contains("table <wgex_")); #expect(text.contains("> const {"))
        #expect(text.split(separator: "\n").filter { $0.contains("from any to <wgex_") }.count == 1)
        let changed = try PacketFilterRenderer.render(phase: .error, modifiers: .init(), context: .init(
            underlay: PFInterface("en0"), tunnelRanges: Array(ranges.dropLast()), consoleUID: 501,
        ))
        #expect(text.split(separator: "\n").first != changed.split(separator: "\n").first)
    }

    @Test
    func `route verification uses one dump for all routes`() async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        try await table.install([harness.route], generation: harness.generation)
        let calls = await kernel.requests.count
        #expect(try await table.observed(harness.journal.snapshot().resources[0]).count == 1)
        #expect(await kernel.requests.count == calls)
        #expect(await kernel.dumpCount == 1)
    }

    @Test
    func `underlay loss then restoration recovers failed protection without a user request`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        await #expect(throws: (any Error).self) {
            try await harness.controller.networkChanged(trigger: .configuration, underlay: .init(
                snapshot: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []), satisfied: false,
            ))
        }
        #expect(await harness.controller.status.protection == .blocked)
        try await harness.controller.networkChanged(trigger: .configuration, underlay: .init(
            snapshot: ControllerHarness.underlay, satisfied: true,
        ))
        harness.clock.advance(.seconds(5)); try await harness.controller.tick()
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test
    func `merged network debounce has a trailing edge and a three second maximum`() {
        var model = NetworkEventDebounce()
        model.receive(at: .zero)
        #expect(model.deadline == .milliseconds(500))
        for milliseconds in stride(from: 400, through: 2800, by: 400) {
            model.receive(at: .milliseconds(milliseconds))
        }
        #expect(model.deadline == .seconds(3))
        let early = model.take(at: .milliseconds(2999)), ready = model.take(at: .seconds(3))
        #expect(!early); #expect(ready); #expect(model.deadline == nil)
    }

    @Test(arguments: ["verify", "routes.install", "engine.up"])
    func `failed connect re-drives durable intent after backoff`(_ fault: String) async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        harness.trace.fail(at: fault)
        await #expect(throws: (any Error).self) { _ = try await harness.start() }
        let failed = await harness.controller.currentGeneration
        #expect(await harness.controller.status.protection == .blocked)
        #expect(harness.journal.snapshot().intent != nil)
        harness.clock.advance(.seconds(4))
        try await harness.controller.tick()
        #expect(await harness.controller.currentGeneration == failed)
        harness.clock.advance(.seconds(1))
        try await harness.controller.tick()
        #expect(await harness.controller.currentGeneration.rawValue > failed.rawValue)
        #expect(await harness.controller.status.protection == .protected)
        #expect(harness.trace.calls.filter { $0 == "resolver.resolve" }.count >= 2)
    }

    @Test
    func `route changes are accepted and a continuous burst has a two second deadline`() throws {
        let data = try NetworkPortHarness.fixture("RouteMessages/change-v4.hex")
        let bytes = try data.split(whereSeparator: \.isWhitespace).map { try #require(UInt8($0, radix: 16)) }
        #expect(try RouteNotification.parse(Data(bytes)).type == 3)
        var model = RouteMonitorModel(ownPID: 123)
        for milliseconds in stride(from: 0, through: 1900, by: 100) {
            let accepted = model.receive(.init(type: 3, index: 4, pid: 456), at: .milliseconds(milliseconds))
            #expect(accepted)
        }
        #expect(model.deadline == .seconds(2))
        let ready = model.takeReconciliation(at: .seconds(2))
        #expect(ready)
    }

    @Test
    func `readiness drains a thousand datagrams through EAGAIN`() throws {
        let hex = try NetworkPortHarness.fixture("RouteMessages/change-v4.hex")
        let bytes = try hex.split(whereSeparator: \.isWhitespace).map { try #require(UInt8($0, radix: 16)) }
        var reads = 0, emitted = 0
        drainRouteNotifications(read: {
            reads += 1
            return reads <= 1000 ? Data(bytes) : nil
        }, emit: { _ in emitted += 1 })
        #expect(reads == 1001); #expect(emitted == 1000)
    }

    @Test
    func `route stream retains a thousand message burst`() async {
        let monitor = FakeRouteMonitor()
        let stream = monitor.start()
        for index in 1 ... 1000 {
            monitor.send(.init(type: 3, index: UInt16(index), pid: 456))
        }
        monitor.stop()
        var received: [UInt16] = []
        for await event in stream {
            received.append(event.index)
        }
        #expect(received == (1 ... 1000).map(UInt16.init))
    }

    @Test
    func `journal retains at most current and previous generation entries`() throws {
        let harness = try ControllerHarness()
        for _ in 0 ..< 100 {
            let generation = try harness.journal.allocate(intent: nil)
            for step in DaemonStep.allCases {
                try harness.journal.mutate(generation: generation) {
                    $0.entries.append(.init(generation: generation, step: step, action: .didApply))
                }
            }
        }
        let document = harness.journal.snapshot()
        #expect(Set(document.entries.map(\.generation.rawValue)) == [99, 100])
        #expect(try JSONEncoder().encode(document).count < 8192)
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == document)
    }
}

private actor RetryingUnderlayRead {
    private(set) var reads = 0
    func read() throws -> UnderlayEvent {
        reads += 1
        if reads == 1 {
            throw HostTestError.injected
        }
        return .init(snapshot: ControllerHarness.underlay, satisfied: true)
    }
}

private final class CountingOwnerRepository: ProfileRepository {
    private struct State { var records: [UUID: RegisteredProfile] = [:]; var reads = 0 }
    private let state = Mutex(State())
    var reads: Int {
        state.withLock { $0.reads }
    }

    func load(_ id: UUID) -> RegisteredProfile? {
        state.withLock { $0.records[id] }
    }

    func save(_ profile: RegisteredProfile) {
        state.withLock { $0.records[profile.registration.profile.id] = profile }
    }

    func remove(_ id: UUID) {
        state.withLock { _ = $0.records.removeValue(forKey: id) }
    }

    func all() -> [RegisteredProfile] {
        state.withLock { $0.reads += 1; return Array($0.records.values) }
    }
}
