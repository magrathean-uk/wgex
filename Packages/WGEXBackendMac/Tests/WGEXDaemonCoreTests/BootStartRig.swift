// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

/// Collects the controller's operation timing lines.
package final class OperationLogSink: Sendable {
    private let storage = Mutex<[String]>([])
    package func append(_ line: String) {
        storage.withLock { $0.append(line) }
    }

    package var lines: [String] {
        storage.withLock { $0 }
    }

    package var expiries: [String] {
        lines.filter { $0.hasPrefix("operation expired") }
    }

    /// The runtime's refusal to declare recovery over while the controller still needs it (M1-31).
    package var recoveryGuardLines: [String] {
        lines.filter { $0.hasPrefix("recovery guard:") }
    }
}

/// Records every published status in order, from the moment it is attached.
package final class StatusRecorder: Sendable {
    private final class Box: Sendable {
        let storage = Mutex<[TunnelStatus]>([])
    }

    private let box = Box()
    private let consumer = Mutex<Task<Void, Never>?>(nil)
    package init(_ stream: AsyncStream<DaemonServiceEvent>) {
        let box = box
        let task = Task {
            for await event in stream {
                if case let .status(status) = event.event {
                    box.storage.withLock { $0.append(status) }
                }
            }
        }
        consumer.withLock { $0 = task }
    }

    package var statuses: [TunnelStatus] {
        box.storage.withLock { $0 }
    }

    /// Returns once every status the controller has published so far has been recorded. The statuses reach this recorder
    /// through an unbounded-latency stream, so a negative check on `statuses` that does not fence first can pass falsely.
    /// A published status carrying a unique marker in its `sequence` (which the controller itself never sets) fences them:
    /// the stream is ordered.
    package func flush(_ controller: TunnelController) async throws {
        let marker = Self.nextMarker.withLock { value in value += 1; return value }
        await controller.publishFence(marker)
        try await waitForCondition { statuses.contains { $0.sequence == marker } }
    }

    private static let nextMarker = Mutex<UInt64>(0xFE00_0000)

    deinit { consumer.withLock { $0 }?.cancel() }
}

package extension TunnelController {
    /// Publishes the current status once, tagged so a `StatusRecorder` can recognise it; the tag is not kept.
    func publishFence(_ marker: UInt64) {
        let saved = snapshot.sequence
        snapshot.sequence = marker
        publish()
        snapshot.sequence = saved
    }
}

/// A task whose completion is observable without awaiting it: a regression that parks the task fails the caller's bounded
/// wait (`waitForCondition`, 5 s) instead of hanging the run on an unbounded `await task.value`.
package final class Watched<Value: Sendable>: Sendable {
    private final class Flag: Sendable {
        let value = Mutex(false)
    }

    private let flag = Flag()
    private let task: Task<Value, any Error>
    package init(_ body: @escaping @Sendable () async throws -> Value) {
        let flag = flag
        task = Task { defer { flag.value.withLock { $0 = true } }; return try await body() }
    }

    package var isFinished: Bool {
        flag.value.withLock { $0 }
    }

    /// The outcome, once the task ends within the bounded wait.
    package func outcome() async throws -> Result<Value, any Error> {
        try await waitForCondition { isFinished }
        return await task.result
    }

    package func cancel() {
        task.cancel()
    }
}

/// Parks the first secure-install read, which is the first suspension inside startup reconciliation proper.
package actor ReconciliationGate: SecureInstallChecking {
    private let gate: StepGate
    private var armed = true
    package init(gate: StepGate) {
        self.gate = gate
    }

    package func status() async -> SecureInstallReport {
        if armed {
            armed = false
            try? await gate.adapterCall(.validateSecrets, generation: .initial)
        }
        return VerifiedSecureInstall().status()
    }

    package func perform() async -> SecureInstallReport {
        await status()
    }
}

/// A secure-install adapter that parks its first status read, insensitively to cancellation (as a real adapter would be),
/// and runs on the caller's executor: the caller resumes in the same actor job that `release()` scheduled. `returned`
/// counts reads that have come back, so a test can fence on the stale caller's resumption. The parked read answers with
/// `firstState`; every later read answers with the state set by `answerLater` (verified until a test says otherwise).
package final class ParkingSecureInstall: SecureInstallChecking {
    private let parking = Parking()
    private let first = Mutex(true)
    private let returns = Mutex(0)
    private let later = Mutex<SecureInstallReport.State>(.verified)
    private let firstState: SecureInstallReport.State
    private let notifications: AsyncStream<Void>
    private let sink: AsyncStream<Void>.Continuation
    package init(firstState: SecureInstallReport.State = .verified) {
        self.firstState = firstState
        (notifications, sink) = AsyncStream.makeStream()
    }

    package var returned: Int {
        returns.withLock { $0 }
    }

    package func status() async -> SecureInstallReport {
        if first.withLock({ value in defer { value = false }; return value }) {
            let sink = sink
            await parking.park(cancellable: false) { sink.yield(()) }
            returns.withLock { $0 += 1 }
            var report = VerifiedSecureInstall().status()
            report.state = firstState
            return report
        }
        var report = VerifiedSecureInstall().status()
        report.state = later.withLock { $0 }
        return report
    }

    /// What every read after the parked one answers from now on.
    package func answerLater(_ state: SecureInstallReport.State) {
        later.withLock { $0 = state }
    }

    package func perform() async -> SecureInstallReport {
        await status()
    }

    package func wait() async {
        for await _ in notifications {
            return
        }
    }

    package func release() {
        parking.release()
    }
}

/// The rig's manual clock as the controller's watchdog clock, with one hook on `now`. The controller reads `now` inside every
/// serial-slot assignment (`operation`'s didSet), so the hook runs synchronously inside the actor turn that makes the
/// assignment: a test can fire a deadline at an exact point of a stage's own turn. The hook returns true once it has fired.
package final class HookedClock: DaemonClock {
    private let base = Mutex<HostClock?>(nil)
    private let hook = Mutex<(@Sendable () -> Bool)?>(nil)
    private let fires = Mutex(0)
    package init() {}

    /// Bound by `BootRig.make` to the rig's own clock.
    package func bind(_ clock: HostClock) {
        base.withLock { $0 = clock }
    }

    package func arm(_ body: @escaping @Sendable () -> Bool) {
        hook.withLock { $0 = body }
    }

    package var fired: Bool {
        fires.withLock { $0 > 0 }
    }

    private var clock: HostClock {
        base.withLock { $0 } ?? HostClock()
    }

    package var now: Duration {
        if let body = hook.withLock({ $0 }), body() {
            hook.withLock { $0 = nil }
            fires.withLock { $0 += 1 }
        }
        return clock.now
    }

    package var wallNow: Date {
        clock.wallNow
    }

    package func sleep(for duration: Duration) async throws {
        try await clock.sleep(for: duration)
    }
}

/// A synchronous, thread-holding stand-in for a blocking syscall or cgo call. It parks the calling thread, so an
/// adapter that runs on the controller actor starves the actor.
package final class ThreadBlock: Sendable {
    private let release = DispatchSemaphore(value: 0)
    private let count = Mutex(0)
    package init() {}
    package var entered: Bool {
        entries > 0
    }

    /// How many calls have parked a thread here so far: the number of pool threads an adapter has leaked.
    package var entries: Int {
        count.withLock { $0 }
    }

    package func block() {
        count.withLock { $0 += 1 }
        release.wait()
    }

    /// Releases one parked thread, or every thread that parks later if none is parked yet.
    package func open() {
        release.signal()
    }
}

package struct BlockingEngineFactory: DaemonEngineCreating {
    package let base: any DaemonEngineCreating
    package let block: ThreadBlock
    package func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
        block.block()
        return try await base.create(configuration: configuration, generation: generation)
    }
}

/// Blocks the calling thread in `configure` or in the post-configure identity read, as selected.
package struct BlockingDevice: TunnelDeviceConfiguring {
    package enum Point: Sendable { case configure, confirm }
    package let base: any TunnelDeviceConfiguring
    package let point: Point
    package let block: ThreadBlock
    package func configure(_ identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16, generation: Generation) async throws {
        if point == .configure {
            block.block()
        }
        try await base.configure(identity, addresses: addresses, mtu: mtu, generation: generation)
    }

    package func removeAddresses(_ identity: TunnelIdentity, generation: Generation) async throws {
        try await base.removeAddresses(identity, generation: generation)
    }

    package func identity(afterConfiguring identity: TunnelIdentity) async throws -> TunnelIdentity {
        try await base.identity(afterConfiguring: identity)
    }

    package func identity(afterConfiguring identity: TunnelIdentity, engine: any EngineControlling?) async throws -> TunnelIdentity {
        if point == .confirm {
            block.block()
        }
        return try await base.identity(afterConfiguring: identity, engine: engine)
    }
}

/// Parks the first policy read of one kind that satisfies `when`, so a test can hold a controller task inside that read.
/// Insensitive to cancellation, like the pf adapter it stands in for. `returned` counts parked reads that have come back.
package final class PolicyReadGate: Sendable {
    package enum Read: Sendable { case verification, current }
    private let read: Read
    private let when: (@Sendable (ControllerHarness) -> Bool)?
    private let armed: Mutex<Bool>
    private let bound = Mutex<ControllerHarness?>(nil)
    private let returns = Mutex(0)
    private let parking = Parking()
    private let notifications: AsyncStream<Void>
    private let sink: AsyncStream<Void>.Continuation
    package init(_ read: Read, armed: Bool = true, when: (@Sendable (ControllerHarness) -> Bool)? = nil) {
        self.read = read; self.when = when; self.armed = Mutex(armed); (notifications, sink) = AsyncStream.makeStream()
    }

    package func arm() {
        armed.withLock { $0 = true }
    }

    /// Gives `when` the harness whose state it inspects.
    package func bind(_ harness: ControllerHarness) {
        bound.withLock { $0 = harness }
    }

    package var returned: Int {
        returns.withLock { $0 }
    }

    fileprivate func before(_ kind: Read) async {
        guard kind == read else { return }
        if let when {
            guard let harness = bound.withLock({ $0 }), when(harness) else { return }
        }
        guard armed.withLock({ value in defer { value = false }; return value }) else { return }
        let sink = sink
        await parking.park(cancellable: false) { sink.yield(()) }
        returns.withLock { $0 += 1 }
    }

    package func wait() async {
        for await _ in notifications {
            return
        }
    }

    package func release() {
        parking.release()
    }
}

/// The policy port with its verification or current-policy read held by a `PolicyReadGate`.
package struct GatedPolicy: DaemonPolicyManaging {
    package let base: any DaemonPolicyManaging
    package let gate: PolicyReadGate
    package func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        try await base.apply(policy)
    }

    package func current() async -> PacketFilterPolicy {
        await gate.before(.current)
        return await base.current()
    }

    package func setModifiers(_ modifiers: PolicyModifiers) async throws {
        try await base.setModifiers(modifiers)
    }

    package func acquireToken(existing: String?) async throws -> String {
        try await base.acquireToken(existing: existing)
    }

    package func releaseToken(_ token: String) async throws {
        try await base.releaseToken(token)
    }

    package func verification() async -> PFVerificationStatus {
        await gate.before(.verification)
        return await base.verification()
    }

    package func verifyEvaluation() async throws {
        try await base.verifyEvaluation()
    }

    package func configureProfile(_ profile: TunnelProfile) async throws {
        try await base.configureProfile(profile)
    }

    package func repairLiveness(existingToken: String?, failure: any Error) async throws -> String {
        try await base.repairLiveness(existingToken: existingToken, failure: failure)
    }
}

package extension ControllerHarness {
    /// Whether the journal's newest entry is `action` of `step`, read from disk.
    func lastJournalEntry(is step: DaemonStep, _ action: DaemonJournalEntry.Action) -> Bool {
        guard let last = try? DaemonJournal(directory: directory).snapshot().entries.last else { return false }
        return last.step == step && last.action == action
    }
}

package extension DaemonPorts {
    /// The same ports with the policy port's reads held by `gate`.
    func gatingPolicy(_ gate: PolicyReadGate) -> DaemonPorts {
        DaemonPorts(
            engineFactory: engineFactory, routes: routes, dns: dns, policy: GatedPolicy(base: policy, gate: gate),
            resolver: resolver, device: device, verifier: verifier, reality: reality,
        )
    }

    /// The same ports with the engine factory replaced.
    func replacingEngineFactory(_ factory: any DaemonEngineCreating) -> DaemonPorts {
        DaemonPorts(
            engineFactory: factory, routes: routes, dns: dns, policy: policy,
            resolver: resolver, device: device, verifier: verifier, reality: reality,
        )
    }
}

package extension TunnelController {
    /// Puts an engine handle in the map, as a start that ran before a relaunch would have left it.
    func adopt(_ engine: any EngineControlling, generation: Generation) {
        engines[generation] = engine
    }

    /// The invariant of the boot hand-over: a pending boot start never coexists with an empty serial slot.
    var bootStartSlotIsEmpty: Bool {
        startup.bootStart != nil && operation == nil
    }

    /// One recovery heartbeat tick (the production port is `verifyRecoveryProtection`). Returns whether, at that moment, a
    /// boot start was pending with the serial slot empty (the heartbeat then starts its own operation beside it). The
    /// check and the call share one actor turn.
    func heartbeatProbe() async throws -> Bool {
        let violated = bootStartSlotIsEmpty && needsRecovery && requiresStartupProtection
        try await verifyRecoveryProtection()
        return violated
    }
}

/// A rebooted daemon: a persisted intent, a fresh controller and the production runtime wiring (DaemonComposition.run).
package struct BootRig: Sendable {
    package let harness: ControllerHarness
    package let controller: TunnelController
    package let runtime: DaemonRuntime
    package let log: OperationLogSink
    package let recorder: StatusRecorder
    package let heartbeat: Bool

    /// What the rebooted daemon finds persisted: the intent of the tunnel that was up, no intent at all, or no intent and
    /// one start-before-login profile (whose boot intent reconciliation then reserves).
    package enum Persisted: Sendable { case intent, none, bootProfile }

    /// `heartbeat` wires the production recovery heartbeat into the runtime (DaemonComposition.run), which sleeps 5 s on the
    /// manual clock; it is off by default so the existing 5 s backoff waits stay unambiguous.
    package static func make(
        steps: any DaemonStepObserving = UninterruptedDaemonSteps(),
        secureInstall: any SecureInstallChecking = VerifiedSecureInstall(),
        persisted: Persisted = .intent,
        heartbeat: Bool = false,
        watchdogClock: HookedClock? = nil,
        portsTransform: (@Sendable (DaemonPorts) -> DaemonPorts)? = nil,
    ) async throws -> BootRig {
        let harness = try ControllerHarness()
        watchdogClock?.bind(harness.clock)
        try await harness.install(); _ = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        if persisted != .intent {
            if persisted == .bootProfile {
                var profile = harness.profile; profile.macOptions.startBeforeLogin = true
                try await harness.registry.installProfile(profile, expectedRevision: 1, connectionUID: ControllerHarness.uid)
                try await harness.registry.setStartBeforeLogin(profile.id, enabled: true, connectionUID: ControllerHarness.uid)
            }
            try await harness.journal.mutate(generation: harness.controller.currentGeneration) { $0.intent = nil }
        }
        let log = OperationLogSink()
        let controller = try harness.replacementController(
            steps: steps, secureInstall: secureInstall, operationLog: log.append, operationClock: watchdogClock,
            portsTransform: portsTransform,
        )
        let runtime = DaemonRuntime(clock: harness.clock)
        await controller.setStartupRetry { [weak runtime] in await runtime?.retryNow() }
        return BootRig(
            harness: harness, controller: controller, runtime: runtime, log: log,
            recorder: StatusRecorder(controller.wireEvents.observe()), heartbeat: heartbeat,
        )
    }

    package var runtimePorts: DaemonRuntime.Ports {
        let controller = controller, log = log
        let beat: (@Sendable () async throws -> Void)? = if heartbeat {
            { try await controller.verifyRecoveryProtection() }
        } else {
            nil
        }
        return .init(
            startListener: {},
            setRecovering: { value in
                if value {
                    await controller.markStartupRecovering()
                }
            },
            reconcile: { try await controller.reconcileAtStartup() },
            startMonitors: {},
            block: { _ in },
            shouldRetry: { await controller.shouldRetryStartup() },
            shutdown: { try await controller.shutdownCleanly() },
            prepareBlocking: { try await controller.prepareStartupBlocking() },
            revision: { await controller.startupControlRevision() },
            failure: { reason, revision in try await controller.recoveryFailed(reason, expectedControlID: revision) },
            heartbeat: beat,
            recoveryIncomplete: { await controller.needsRecovery },
            log: { log.append($0) },
        )
    }

    /// Starts the daemon's recovery loop in the background.
    package func run() -> Task<Void, Never> {
        let runtime = runtime, ports = runtimePorts
        return Task { await runtime.run(ports: ports) }
    }

    package func count(_ call: String, since offset: Int = 0) -> Int {
        harness.trace.calls.dropFirst(offset).filter { $0 == call }.count
    }

    package func waitForPhase(_ matches: @escaping @Sendable (TunnelPhase) -> Bool) async throws {
        let controller = controller
        try await waitForCondition { await matches(controller.status.phase) }
    }

    package func waitForPendingSleep(_ duration: Duration) async throws {
        let clock = harness.clock
        try await waitForCondition { clock.pendingSleeps.contains(duration) }
    }

    package func settle() async {
        for _ in 0 ..< 1000 {
            await Task.yield()
        }
    }
}

package extension TunnelPhase {
    var isActive: Bool {
        if case .active = self {
            true
        } else {
            false
        }
    }

    var isFailed: Bool {
        if case .failed = self {
            true
        } else {
            false
        }
    }
}

/// A bounded wait that reports, rather than records, a timeout: the caller states what the failure means.
package func eventually(within limit: Duration = .seconds(3), _ condition: @Sendable () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + limit
    while await !condition() {
        guard ContinuousClock.now < deadline else { return false }
        try? await Task.sleep(for: .milliseconds(1))
    }
    return true
}
