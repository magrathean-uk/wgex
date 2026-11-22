// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
@testable import WGEXCore
import WGEXDaemonClient
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// A latch a test holds closed to keep the startup input refresh, and so the restore after it, suspended.
private actor RestoreLatch {
    private var released = false
    private(set) var entered = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        entered = true
        guard !released else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        released = true
        let pending = waiters; waiters = []
        pending.forEach { $0.resume() }
    }
}

/// Holds the first console-user check after it is armed, so a test can pause one request inside authorisation: after the
/// startup fence let it through and before its status is measured. Every other check passes at once.
private actor AuthorisationGate {
    private var armed = false
    private var released = false
    private(set) var entered = false
    private var waiter: CheckedContinuation<Void, Never>?

    func arm() {
        armed = true
    }

    func check() async -> Bool {
        guard armed, !entered else { return true }
        entered = true
        if !released {
            await withCheckedContinuation { waiter = $0 }
        }
        return true
    }

    func release() {
        released = true
        waiter?.resume(); waiter = nil
    }
}

/// Records every request a real client sends before the daemon sees it.
private actor RecordingTransport: XPCTransport {
    private let base: InMemoryXPCTransport
    private(set) var requests: [Request] = []

    init(_ dispatcher: DaemonDispatcher) {
        base = InMemoryXPCTransport(daemon: dispatcher, peer: CompositionFixture.peer(ControllerHarness.uid))
    }

    func connect(callbacks: XPCClientCallbacks) async throws {
        try await base.connect(callbacks: callbacks)
    }

    func send(_ envelope: Data, secrets: Data?) async throws -> Data {
        try requests.append(Envelope.decode(envelope).body)
        return try await base.send(envelope, secrets: secrets)
    }

    func invalidate() async {
        await base.invalidate()
    }
}

private struct IdleService: ServiceControlling {
    var state: AsyncStream<ServiceState> {
        AsyncStream { $0.finish() }
    }

    func register() async throws(ServiceError) {
        throw .hostGuard
    }

    func unregister() async throws(ServiceError) {
        throw .hostGuard
    }

    func openApproval() {}
}

/// A daemon restarted over a journal that still holds a tunnel pass: startup must restore the error policy first.
private struct RestartRig {
    static let leftBehind = PacketFilterPolicy.connected(interfaceName: "utun9", endpoints: ["192.0.2.1"])
    let harness: ControllerHarness
    let composition: DaemonComposition
    let runtime: DaemonRuntime

    init(
        reportingClock: XPCClock = .continuous, sequence: (@Sendable () throws -> UInt64)? = nil, gate: AuthorisationGate? = nil,
    ) async throws {
        let harness = try ControllerHarness()
        self.harness = harness
        try await harness.install()
        try harness.journal.mutate(generation: nil) {
            $0.intent = .init(profileID: harness.profile.id, ownerUID: ControllerHarness.uid)
            $0.pfPolicy = Self.leftBehind
        }
        composition = try DaemonComposition(
            controller: harness.replacementController(), daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in await gate?.check() ?? true }, hasAdminRight: { _, _ in true }),
            nextStatusSequence: sequence, reportingClock: reportingClock,
        )
        runtime = DaemonRuntime(clock: harness.clock)
    }

    func run(
        refresh: @escaping @Sendable () async throws -> Void = {}, refreshBound: Duration = DaemonComposition.startupRefreshBound,
    ) -> Task<Void, Never> {
        Task {
            await composition.run(
                runtime: runtime, startListener: {}, startMonitors: {}, refreshUnderlay: refresh, refreshBound: refreshBound,
            )
        }
    }

    func client(_ transport: any XPCTransport) -> DaemonClient {
        DaemonClient(transport: transport, clientVersion: "test", clientBuild: 11)
    }

    func raw(onEvent: (@Sendable (Event) -> Void)? = nil) async throws -> InMemoryXPCTransport {
        let transport = InMemoryXPCTransport(daemon: composition.dispatcher, peer: CompositionFixture.peer(ControllerHarness.uid))
        try await transport.connect(callbacks: .init(event: { data in
            if let onEvent, let event = try? WireCodec.decode(Event.self, from: data) {
                onEvent(event)
            }
        }))
        guard case .hello = try await Self.call(transport, .hello(clientVersion: "test", clientBuild: 11)) else {
            throw HostTestError.injected
        }
        return transport
    }

    static func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }

    func finish(_ running: Task<Void, Never>) async {
        await running.value
        await runtime.stop()
        await composition.dispatcher.stopHeartbeat()
    }

    static func json(_ result: CLIResult) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any])
    }
}

/// A manual reporting clock: the dispatcher's holds and the refresh bound expire only when the test advances it.
private func manual(_ clock: HostClock) -> XPCClock {
    XPCClock(now: { Double(clock.now.components.seconds) }, sleep: { try await clock.sleep(for: $0) })
}

private func untilPending(_ clock: HostClock, _ duration: Duration) async throws {
    try await waitForCondition { clock.pendingSleeps.contains(duration) }
}

/// M03-T01 review rounds 1 and 2: DEC-011's first publication as a fresh client sees it, kept as `startup` (DEC-018), and
/// startup stays answerable.
@Suite(.timeLimit(.minutes(1)))
private struct FirstPublicationTests {
    @Test
    func `a cold CLI started in the restore reads startup sequence 1 with the restored error policy and no hidden read`() async throws {
        // A manual reporting clock: the read's fence hold never expires on wall time while the test holds the restore.
        let rig = try await RestartRig(reportingClock: manual(HostClock()))
        let restoring = RestoreLatch()
        let running = rig.run(refresh: { await restoring.wait() })
        try await waitForCondition { await restoring.entered }
        let transport = RecordingTransport(rig.composition.dispatcher)
        let client = rig.client(transport)
        let status = Task { await WGEXCLICore(client: client, service: IdleService()).run(["status", "--json"]) }
        try await waitForCondition { await transport.requests.contains(.statusTelemetry) }
        #expect(!rig.harness.trace.calls.contains("pf.error"))
        await restoring.release()
        let result = await status.value
        let fields = try RestartRig.json(result)
        let startup = try #require(fields["startup"] as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(startup["sequence"] as? UInt64 == 1)
        #expect(startup["journalPolicy"] as? String == "error")
        #expect(startup["protection"] as? String == "blocked")
        // The read waited at the fence, yet its current sample is measured after the opening, never the startup record.
        #expect((fields["sequence"] as? UInt64 ?? 0) > 1)
        // Connection setup took no status read of its own, so nothing spent sequence 1 unseen.
        #expect(await transport.requests == [
            .hello(clientVersion: "test", clientBuild: 11), .subscribeEvents(includeLogs: false), .statusTelemetry,
        ])
        await client.disconnect()
        await rig.finish(running)
    }

    @Test
    func `a CLI that connects after startup with no subscriber reads startup as sequence 1 beside a later current sample`() async throws {
        let rig = try await RestartRig()
        let running = rig.run()
        // Startup completes with nobody connected: sequence 1 reaches no subscriber.
        await running.value
        #expect(rig.harness.trace.calls.contains("pf.error"))
        #expect(await !rig.composition.dispatcher.hasSubscribers)
        let transport = RecordingTransport(rig.composition.dispatcher)
        let client = rig.client(transport)
        let result = await WGEXCLICore(client: client, service: IdleService()).run(["status", "--json"])
        let fields = try RestartRig.json(result)
        let startup = try #require(fields["startup"] as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(startup["sequence"] as? UInt64 == 1)
        #expect(startup["journalPolicy"] as? String == "error")
        #expect(startup["protection"] as? String == "blocked")
        #expect(startup["activeProfileID"] as? String == rig.harness.profile.id.uuidString)
        #expect(startup["measuredAt"] is String)
        #if WGEX_LAB_BUILD
            #expect(startup.keys.contains("ownerPFToken"))
        #else
            #expect(startup["ownerPFToken"] == nil)
        #endif
        // The current sample is the CLI's own fresh measurement.
        #expect((fields["sequence"] as? UInt64 ?? 0) > 1)
        #expect(fields["journalPolicy"] as? String == "error")
        #expect(await transport.requests == [
            .hello(clientVersion: "test", clientBuild: 11), .subscribeEvents(includeLogs: false), .statusTelemetry,
        ])
        // The client API reads the same record.
        let telemetry = try await client.statusTelemetry()
        #expect(telemetry.startup?.status.sequence == 1)
        #expect(telemetry.startup?.journalPolicy == .error)
        #expect(telemetry.startup?.status.protection == .blocked)
        #expect(telemetry.status.sequence > 1)
        await client.disconnect()
        await rig.finish(running)
    }

    @Test
    func `a stop served after startup leaves startup as captured while the current sample shows the state after it`() async throws {
        let rig = try await RestartRig()
        let running = rig.run()
        await running.value
        let client = rig.client(RecordingTransport(rig.composition.dispatcher))
        let captured = try #require(try await client.statusTelemetry().startup)
        #expect(captured.status.sequence == 1)
        #expect(try await client.request(.stop(profileID: rig.harness.profile.id, reason: .userRequested)) == .ok)
        // A cold CLI reads after the stop.
        let cold = rig.client(RecordingTransport(rig.composition.dispatcher))
        let result = await WGEXCLICore(client: cold, service: IdleService()).run(["status", "--json"])
        let fields = try RestartRig.json(result)
        let startup = try #require(fields["startup"] as? [String: Any])
        #expect(result.exitCode == 0)
        #expect(startup["sequence"] as? UInt64 == 1)
        #expect(startup["journalPolicy"] as? String == "error")
        #expect(startup["protection"] as? String == "blocked")
        #expect(startup["activeProfileID"] as? String == rig.harness.profile.id.uuidString)
        #expect(startup["measuredAt"] as? String == captured.status.measuredAt.map { ISO8601DateFormatter().string(from: $0) })
        // The current sample shows the state after the stop, never the startup state.
        #expect(fields["activeProfileID"] is NSNull)
        #expect(fields["journalPolicy"] as? String == "disconnected")
        #expect(fields["protection"] as? String != "blocked")
        #expect((fields["sequence"] as? UInt64 ?? 0) > 1)
        #expect(try await client.statusTelemetry().startup == captured)
        await cold.disconnect()
        await client.disconnect()
        await rig.finish(running)
    }

    @Test
    func `a stop and a registration sent during the restore are served only after the first publication`() async throws {
        let registeredAtFirst = Mutex<Bool?>(nil)
        let counter = StatusPublicationJournal()
        let registration = Mutex<URL?>(nil)
        // A manual reporting clock: the held read and commands never expire on wall time while the test holds the restore.
        let rig = try await RestartRig(reportingClock: manual(HostClock()), sequence: {
            let sequence = try counter.next()
            if sequence == 1, let path = registration.withLock({ $0 })?.path {
                registeredAtFirst.withLock { $0 = FileManager.default.fileExists(atPath: path) }
            }
            return sequence
        })
        let base = rig.harness.profile
        let other = TunnelProfile(
            name: "Other", interface: base.interface, peers: base.peers, secrets: base.secrets, transport: base.transport,
            protection: base.protection, onDemand: base.onDemand, macOptions: base.macOptions,
        )
        registration.withLock {
            $0 = rig.harness.root.appendingPathComponent("profiles").appendingPathComponent(other.id.uuidString + ".json")
        }
        let restoring = RestoreLatch()
        let running = rig.run(refresh: { await restoring.wait() })
        try await waitForCondition { await restoring.entered }
        let transport = try await rig.raw()
        let answered = Mutex(0)
        let read = Task { try await RestartRig.call(transport, .statusTelemetry) }
        let stop = Task {
            defer { answered.withLock { $0 += 1 } }
            return try await RestartRig.call(transport, .stop(profileID: rig.harness.profile.id, reason: .userRequested))
        }
        let register = Task {
            defer { answered.withLock { $0 += 1 } }
            return try await RestartRig.call(transport, .installProfileCAS(other, expectedRevision: nil))
        }
        // All three wait at the fence; served at once instead, the stop and the registration would both be answered here.
        let dispatcher = rig.composition.dispatcher
        try await waitForCondition { await (dispatcher.startupFence?.waiting ?? 0) == 3 || answered.withLock { $0 } == 2 }
        #expect(answered.withLock { $0 } == 0)
        #expect(!rig.harness.trace.calls.contains("pf.error"))
        await restoring.release()
        // The first publication, as `startup`, carries the restored policy with the intent the stop has not yet ended ...
        guard case let .statusTelemetry(held) = try await read.value, let first = held.startup else { throw HostTestError.injected }
        #expect(first.status.sequence == 1)
        #expect(first.journalPolicy == .error)
        #expect(first.status.protection == .blocked)
        #expect(first.status.activeProfileID == rig.harness.profile.id)
        #expect(held.status.sequence > 1)
        // ... and was numbered before the registration committed.
        #expect(registeredAtFirst.withLock { $0 } == false)
        // Both are served after it. Sent together, the two commands resolve by DEC-012 admission order: the later one may
        // supersede the earlier, which then reports cancellation (a stop) or a refused install; the ordering is the same.
        let stopped = try await stop.value
        let installed = try await register.value
        #expect([.ok, .error(.tunnel(.cancelled))].contains(stopped))
        #expect([.profileRevision(1), .error(.tunnel(.invalidConfiguration(.invalidProfile)))].contains(installed))
        await transport.invalidate()
        await rig.finish(running)
    }

    @Test
    func `a held restore leaves a fresh client connected within its budget and a stop answered recovering`() async throws {
        let reporting = HostClock()
        let numbered = Mutex<[UInt64]>([])
        let counter = StatusPublicationJournal()
        let rig = try await RestartRig(reportingClock: manual(reporting), sequence: {
            let sequence = try counter.next()
            numbered.withLock { $0.append(sequence) }
            return sequence
        })
        let restoring = RestoreLatch()
        let running = rig.run(refresh: { await restoring.wait() }, refreshBound: .seconds(3600))
        try await waitForCondition { await restoring.entered }
        let transport = RecordingTransport(rig.composition.dispatcher)
        let client = rig.client(transport)
        let connecting = Task { try await client.connect() }
        // Connection setup's status read waits for the restore at most StartupFence.statusHold, inside the 5 s status budget.
        try await untilPending(reporting, StartupFence.statusHold)
        #expect(StartupFence.statusHold < RequestDeadline.duration(for: .status))
        reporting.advance(StartupFence.statusHold)
        _ = try await connecting.value
        #expect(await client.currentConnectionState() == .connected(daemonBuild: 10))
        // A stop waits for the first publication within its 30 s budget, then is answered recovering, unserved.
        let stopping = Task { try await client.request(.stop(profileID: rig.harness.profile.id, reason: .userRequested)) }
        let stopHold = RequestDeadline.duration(for: .stop(profileID: rig.harness.profile.id, reason: .userRequested)) - .seconds(1)
        try await untilPending(reporting, stopHold)
        reporting.advance(stopHold)
        await #expect(throws: DaemonError.recovering) { try await stopping.value }
        #expect(!rig.harness.trace.calls.contains("pf.error"))
        // Neither pending answer spent a number, and the unserved stop never ran.
        #expect(numbered.withLock { $0.isEmpty })
        await restoring.release()
        await running.value
        #expect(numbered.withLock { $0.first } == 1)
        #expect(rig.harness.trace.calls.contains("pf.error"))
        #expect(!rig.harness.trace.calls.contains("pf.disconnecting"))
        await client.disconnect()
        await rig.finish(running)
    }

    @Test
    func `a startup input refresh that never returns stops holding the restore at its bound`() async throws {
        let reporting = HostClock()
        let rig = try await RestartRig(reportingClock: manual(reporting))
        let stuck = RestoreLatch()
        let running = rig.run(refresh: { await stuck.wait() })
        try await waitForCondition { await stuck.entered }
        try await untilPending(reporting, DaemonComposition.startupRefreshBound)
        // A read sent after 3 s is still held when the bound passes at 5 s, and carries the first publication as `startup`.
        reporting.advance(.seconds(3))
        let transport = try await rig.raw()
        let read = Task { try await RestartRig.call(transport, .statusTelemetry) }
        try await waitForCondition { reporting.pendingSleeps.contains(StartupFence.statusHold) }
        #expect(!rig.harness.trace.calls.contains("pf.error"))
        reporting.advance(DaemonComposition.startupRefreshBound - .seconds(3))
        guard case let .statusTelemetry(held) = try await read.value else { throw HostTestError.injected }
        #expect(rig.harness.trace.calls.contains("pf.error"))
        let first = try #require(held.startup)
        #expect(first.status.sequence == 1)
        #expect(first.journalPolicy == .error)
        #expect(first.status.protection == .blocked)
        #expect(held.status.sequence > 1)
        await stuck.release()
        await transport.invalidate()
        await rig.finish(running)
    }
}

/// M03-T01 review round 3 (DEC-018): a read held at the startup fence is measured after it opens, like any other read.
@Suite(.timeLimit(.minutes(1)))
private struct HeldReadTests {
    @Test
    func `a read held at the fence measures its current sample after a stop that completed before it, startup unchanged`() async throws {
        let gate = AuthorisationGate()
        // A manual reporting clock: the held read never expires on wall time while the test holds the restore.
        let rig = try await RestartRig(reportingClock: manual(HostClock()), gate: gate)
        let restoring = RestoreLatch()
        let running = rig.run(refresh: { await restoring.wait() })
        try await waitForCondition { await restoring.entered }
        // A subscriber, before the gate is armed, sees the opening publication.
        let events = Mutex<[Event]>([])
        let subscriber = try await rig.raw { event in events.withLock { $0.append(event) } }
        #expect(try await RestartRig.call(subscriber, .subscribeEvents(includeLogs: false)) == .ok)
        let reader = try await rig.raw()
        let answered = Mutex(false)
        let read = Task {
            defer { answered.withLock { $0 = true } }
            return try await RestartRig.call(reader, .statusTelemetry)
        }
        let dispatcher = rig.composition.dispatcher
        try await waitForCondition { await (dispatcher.startupFence?.waiting ?? 0) == 1 }
        // The read is held at the fence; once it opens, the read stops inside authorisation, before it measures anything.
        await gate.arm()
        await restoring.release()
        try await waitForCondition { await gate.entered }
        await running.value
        let statuses: @Sendable () -> [TunnelStatus] = {
            events.withLock { events in
                events.compactMap { event in
                    guard case let .status(status) = event else { return nil }
                    return status
                }
            }
        }
        try await waitForCondition { !statuses().isEmpty }
        #expect(statuses().first?.sequence == 1)
        #expect(statuses().first?.protection == .blocked)
        // A stop completes while the held read has still measured nothing.
        #expect(try await RestartRig.call(subscriber, .stop(profileID: rig.harness.profile.id, reason: .userRequested)) == .ok)
        #expect(!answered.withLock { $0 })
        await gate.release()
        guard case let .statusTelemetry(telemetry) = try await read.value else { throw HostTestError.injected }
        // The current sample is the state after the stop, numbered after everything the subscriber saw ...
        #expect(telemetry.status.activeProfileID == nil)
        #expect(telemetry.journalPolicy == .disconnected)
        #expect(telemetry.status.protection != .blocked)
        #expect(telemetry.status.sequence > 1)
        #expect(telemetry.status.sequence > (statuses().map(\.sequence).max() ?? 0))
        // ... and the first publication travels only as `startup`.
        let startup = try #require(telemetry.startup)
        #expect(startup.status.sequence == 1)
        #expect(startup.journalPolicy == .error)
        #expect(startup.status.protection == .blocked)
        #expect(startup.status.activeProfileID == rig.harness.profile.id)
        await subscriber.invalidate()
        await reader.invalidate()
        await rig.finish(running)
    }
}
