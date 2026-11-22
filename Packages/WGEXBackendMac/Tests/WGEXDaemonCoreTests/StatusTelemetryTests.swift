// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
@testable import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// A latch a test holds closed to keep one startup step suspended.
private actor StartupLatch {
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !released else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        released = true
        let pending = waiters; waiters = []
        pending.forEach { $0.resume() }
    }
}

/// M03-T01, DEC-011: the status telemetry the lab drivers read through `wgex status --json`.
@Suite(.timeLimit(.minutes(1)))
private struct StatusTelemetryTests {
    private static let leftBehind = PacketFilterPolicy.connected(interfaceName: "utun9", endpoints: ["192.0.2.1"])

    @Test
    func `the first publication after a restart is sequence 1 and carries the policy restored at startup`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        // The previous run died with a tunnel pass in the journal; startup replaces it with the error policy.
        try harness.journal.mutate(generation: nil) {
            $0.intent = .init(profileID: harness.profile.id, ownerUID: ControllerHarness.uid)
            $0.pfPolicy = Self.leftBehind
        }
        let restarted = try harness.replacementController()
        // A manual reporting clock: the 3 s status hold and the refresh bound pass only if the test advances it, never by load.
        let reporting = HostClock()
        let fixture = CompositionFixture(harness: harness, controller: restarted, reportingClock: XPCClock(
            now: { Double(reporting.now.components.seconds) }, sleep: { try await reporting.sleep(for: $0) },
        ))
        let runtime = DaemonRuntime(clock: harness.clock)
        let restoring = StartupLatch()
        let running = Task {
            await fixture.composition.run(
                runtime: runtime, startListener: {}, startMonitors: {}, refreshUnderlay: { await restoring.wait() },
            )
        }
        try await waitForCondition { await fixture.composition.dispatcher.startupFence != nil }
        try await fixture.connect()
        let answered = Mutex(false)
        let first = Task {
            let reply = try await fixture.call(.statusTelemetry)
            answered.withLock { $0 = true }
            return reply
        }
        try await waitForCondition { await (fixture.composition.dispatcher.startupFence?.waiting ?? 0) == 1 }
        // The request is held while the error policy is still to be applied; nothing has been published.
        #expect(!answered.withLock { $0 })
        #expect(!harness.trace.calls.contains("pf.error"))
        await restoring.release()
        guard case let .statusTelemetry(telemetry) = try await first.value else { throw HostTestError.injected }
        // The held read carries the first publication as `startup`, beside its own current sample measured after it.
        let startup = try #require(telemetry.startup)
        #expect(startup.status.sequence == 1)
        #expect(startup.journalPolicy == .error)
        #expect(startup.status.protection == .blocked)
        #expect(startup.status.measuredAt != nil)
        #expect(telemetry.status.sequence == 2)
        #expect(telemetry.status.measuredAt != nil)
        guard case let .statusTelemetry(second) = try await fixture.call(.statusTelemetry) else { throw HostTestError.injected }
        #expect(second.status.sequence == 3)
        #expect(second.startup == startup)
        await running.value
        await runtime.stop()
        await fixture.composition.dispatcher.stopHeartbeat()
        await fixture.transport.invalidate()
    }

    @Test
    func `a daemon with nothing to restore publishes sequence 1 as soon as startup ends`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        let runtime = DaemonRuntime(clock: harness.clock)
        try await fixture.connect()
        #expect(try await fixture.call(.subscribeEvents(includeLogs: false)) == .ok)
        await fixture.composition.run(runtime: runtime, startListener: {}, startMonitors: {})
        let statuses: @Sendable () -> [TunnelStatus] = {
            fixture.events.withLock { events in
                events.compactMap { event in
                    guard case let .status(status) = event else { return nil }
                    return status
                }
            }
        }
        try await waitForCondition { !statuses().isEmpty }
        let first = statuses().first
        #expect(first?.sequence == 1)
        #expect(first?.protection == .unprotected)
        guard case let .statusTelemetry(telemetry) = try await fixture.call(.statusTelemetry) else { throw HostTestError.injected }
        #expect(telemetry.status.sequence > 1)
        #expect(telemetry.journalPolicy == .disconnected)
        await runtime.stop()
        await fixture.composition.dispatcher.stopHeartbeat()
        await fixture.transport.invalidate()
    }

    @Test
    func `a publication nobody receives does not spend a sequence number`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        let dispatcher = fixture.composition.dispatcher
        await dispatcher.heartbeat()
        await dispatcher.heartbeat()
        guard case let .statusTelemetry(first) = try await fixture.call(.statusTelemetry) else { throw HostTestError.injected }
        #expect(first.status.sequence == 1)
        // Once a connection subscribes, the same heartbeat is delivered and numbered.
        #expect(try await fixture.call(.subscribeEvents(includeLogs: false)) == .ok)
        await dispatcher.heartbeat()
        try await waitForCondition { fixture.events.withLock { !$0.isEmpty } }
        guard case let .status(published) = fixture.events.withLock({ $0.last }) else { throw HostTestError.injected }
        #expect(published.sequence == 2)
        guard case let .statusTelemetry(next) = try await fixture.call(.statusTelemetry) else { throw HostTestError.injected }
        #expect(next.status.sequence == 3)
        await dispatcher.stopHeartbeat()
        await fixture.transport.invalidate()
    }

    @Test
    func `start before login without a payload needs a daemon-stored key and names its absence`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        #expect(try await fixture.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .profileRevision(1))
        // The CLI sends no secrets, so the daemon's own store decides; with none, the refusal is the one the CLI words.
        let request = Request.setStartBeforeLoginIntent(profileID: harness.profile.id, enabled: true)
        #expect(try await fixture.call(request) == .error(.secretsUnavailable))
        _ = try await fixture.start()
        #expect(try await fixture.call(request) == .ok)
        await fixture.composition.dispatcher.stopHeartbeat()
        await fixture.transport.invalidate()
    }

    @Test
    func `telemetry follows the status owner rule`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        try harness.journal.mutate(generation: nil) { $0.protectionOwnerUID = ControllerHarness.uid }
        let fixture = try CompositionFixture(harness: harness, controller: harness.replacementController())
        let outsider = InMemoryXPCTransport(daemon: fixture.composition.dispatcher, peer: CompositionFixture.peer(777))
        try await outsider.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: outsider.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 11))
        let status = try await call(.status)
        #expect(status == .error(.notAuthorised(.notOwner)))
        #expect(try await call(.statusTelemetry) == status)
        await fixture.composition.dispatcher.stopHeartbeat()
        await outsider.invalidate()
    }

    @Test
    func `the journal policy is the case name without its endpoints`() {
        let policies: [PacketFilterPolicy] = [
            .disconnected, .connecting(resolvers: ["192.0.2.53"], endpoints: ["192.0.2.1"]), Self.leftBehind, .disconnecting,
            .error, .lockdown, .captiveWindow(expires: .distantFuture),
        ]
        #expect(policies.map { JournalPolicyName($0).rawValue } == [
            "disconnected", "connecting", "connected", "disconnecting", "error", "lockdown", "captiveWindow",
        ])
        #expect(Set(JournalPolicyName.allCases.map(\.rawValue)).count == policies.count)
    }

    @Test
    func `the measurement reads the journal policy and the owner token only in Lab builds`() async throws {
        let harness = try ControllerHarness()
        try harness.journal.mutate(generation: nil) {
            $0.pfPolicy = .lockdown
            $0.pfToken = "4660"
        }
        let measurement = try await harness.controller.publicationMeasurement(nextSequence: { 7 })
        #expect(measurement.status.sequence == 7)
        #expect(measurement.journalPolicy == .lockdown)
        #if WGEX_LAB_BUILD
            #expect(measurement.ownerPFToken == "4660")
        #else
            #expect(!Mirror(reflecting: measurement).children.contains { $0.label == "ownerPFToken" })
        #endif
    }
}
