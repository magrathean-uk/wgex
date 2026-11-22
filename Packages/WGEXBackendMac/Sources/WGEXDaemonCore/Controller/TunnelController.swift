// SPDX-License-Identifier: MIT
// Explicit module access keeps mutable bookkeeping out of the package interface.
// swiftformat:disable redundantInternal
import Darwin
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

/// The single mutation owner. A replacement operation cancels AND drains its predecessor before touching ports.
/// The journal generation fence also rejects late continuations from cancellation-insensitive adapters.
public actor TunnelController {
    /// Whether the previous process completed its shutdown policy before exiting.
    public nonisolated let previousShutdownWasClean: Bool
    internal var rotation = EndpointRotationState()
    internal var exclusionState = ExclusionResolutionState()
    internal var maintenanceState = MaintenanceState()
    internal var startup = StartupState()
    internal var cutover = CutoverBookkeeping()
    internal let registry: ProfileRegistry
    internal let journal: any DaemonJournalling
    internal let secrets: any TunnelSecretStoring
    internal let ports: DaemonPorts
    internal let clock: any DaemonClock
    internal let operationClock: any DaemonClock
    internal let steps: any DaemonStepObserving
    /// Sink for the fixed-vocabulary operation timing lines (step names and millisecond counts only).
    internal let operationLog: @Sendable (String) -> Void
    package nonisolated let wireEvents = DaemonEventChannel()
    public nonisolated var serviceEvents: AsyncStream<DaemonServiceEvent> {
        wireEvents.stream
    }

    internal var lastProfileID: UUID?
    internal var pendingTeardownProfileID: UUID?
    internal var stoppingProfile: (id: UUID, generation: Generation)?
    /// Stop commands between their reservation and their end; a start waits for them (`awaitStopInFlight`).
    internal var stopsInFlight = 0 {
        didSet {
            if stopsInFlight == 0 {
                let waiters = stopWaiters.values; stopWaiters = [:]
                waiters.forEach { $0.resume() }
            }
        }
    }

    internal var stopWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]
    internal var consoleSnapshotReceived = false
    public internal(set) var protectionFailureReason: String?
    internal var acceptingRequests = true {
        didSet {
            if !acceptingRequests {
                revokeCommitAdmissions(DaemonFailure.controllerRecoveryRequired)
            }
        }
    }

    /// Admission of control commands (DEC-012): receipts, supersession, holds, fences and commit watermarks, each taken or
    /// moved in one synchronous section. No lane: nothing a command holds spans an await.
    internal let admissions = AdmissionLedger()
    /// The admission whose reservation claimed the current intent; an automatic restart derives from it.
    internal var intentLineage: AdmissionLineage?
    /// The tail of each profile's secret writes. A write is appended in the actor turn it is decided in and runs after the
    /// writes decided before it, so a deletion decided on "nothing retains it" can never land after a newer publication.
    internal var secretWrites: [UUID: Task<Void, Never>] = [:]
    internal var secretWritesQueued: [UUID: Int] = [:]
    /// Publications whose retention claim has not committed yet (an arm, a start-before-login change): a deletion decided
    /// meanwhile treats the profile as retained.
    internal var publishing: [UUID: Int] = [:]
    /// Advanced by every reservation that claims a new intent; a cleanup stop bound to an older value stops nothing.
    internal var intentClaims: UInt64 = 0
    /// The receipt of the newest command whose reservation claimed an intent; an older start, stop or release reaching its
    /// reservation later is superseded, so reservations land in receipt order.
    internal var newestStartAt: UInt64 = 0
    /// The newest receipt handed out (`AdmissionLedger.latestReceipt`).
    internal var controlReceipts: UInt64 = 0
    /// The receipt of the newest command whose reservation ended the intent (a stop, a recovery stop, a cutover rollback);
    /// a start received before it is superseded, so a stop received later always wins.
    internal var intentEndedAt: UInt64 = 0
    internal let secureInstall: any SecureInstallChecking
    /// Startup reconciliation skipped because the bundle was not yet secure; runs once it verifies.
    internal let diagnostics: any DaemonDiagnosticsProviding
    internal var underlay: UnderlaySnapshot
    internal var settings: MacGlobalSettings {
        didSet {
            if settings.lockdown != oldValue.lockdown {
                onDemandInput() // A Lockdown transition voids any on-demand action decided before it.
            }
        }
    }

    internal var snapshot = TunnelStatus.idle
    internal var generation: Generation
    internal var intended: TunnelIntent?
    /// The profile whose tunnel ranges the policy port last accepted in this process (M1-20).
    internal var policyProfileID: UUID?
    internal var operation: Task<Void, any Error>? {
        didSet { operationID = UUID(); lastStep = nil; operationStartedAt = operationClock.now }
    }

    /// The last journalled step the current operation began, and when it began; read for the expiry diagnostic only.
    internal var lastStep: DaemonStep?
    internal var operationStartedAt: Duration?

    internal var operationID = UUID()
    /// Off-actor adapter calls issued and not yet returned, however late (see `offActor(_:_:)`).
    internal var outstandingOffActor: Set<OffActorCall> = []
    internal var abandonedGenerations: Set<Generation> = []
    internal var engines: [Generation: any EngineControlling] = [:]
    internal var eventTask: Task<Void, Never>?
    internal var captiveTask: Task<Void, Never>?
    internal var pendingEvents: [(EngineEvent, Generation)] = []
    /// One controller owns each daemon launch; its live trial keeps this identity across watchdog recovery.
    internal var needsRecovery: Bool {
        didSet {
            if needsRecovery, !oldValue {
                revokeCommitAdmissions(DaemonFailure.controllerRecoveryRequired)
                onDemandRecoveryEntered()
            }
        }
    }

    internal var health: HealthEvaluator<ControllerHealthClock>
    internal var powerModel = PowerMonitorModel()
    internal var loginModel = LoginSessionMonitorModel()
    internal var consoleObservationRevision: UInt64 = 0
    internal var underlayMTU: UInt16 = 1500
    internal var appliedUnderlayMTU: UInt16 = 1500
    internal var appliedPathSatisfied = true
    internal let liveness: any KillSwitchMonitoring
    /// On-demand coordinator state (ADR-030); mutated only on this actor.
    internal var onDemand = OnDemandCoordinator()
    /// Uninstall (M05-T07): the in-memory fence, raised before the durable marker, and the running uninstall.
    internal var uninstallRun = UninstallRun()
    internal let interfaces: any NetworkInterfaceClassifying

    /// Creates the mutation owner. The watchdog uses an awake-time clock; tests may inject that clock independently.
    public init(
        registry: ProfileRegistry, secureInstall: any SecureInstallChecking = UnavailableSecureInstall(), journal: any DaemonJournalling,
        secrets: any TunnelSecretStoring,
        ports: DaemonPorts, underlay: UnderlaySnapshot, clock: any DaemonClock = ContinuousDaemonClock(),
        steps: any DaemonStepObserving = UninterruptedDaemonSteps(),
        diagnostics: any DaemonDiagnosticsProviding = UnavailableDaemonDiagnostics(),
        liveness: any KillSwitchMonitoring = KillSwitchMonitor(),
        underlayMTU: UInt16 = 1500,
        operationClock: any DaemonClock? = nil,
        operationLog: (@Sendable (String) -> Void)? = nil,
        interfaces: any NetworkInterfaceClassifying = StaticInterfaceClassifier(),
    ) {
        self.registry = registry; self.journal = journal; self.secrets = secrets; self.ports = ports
        self.interfaces = interfaces
        self.diagnostics = diagnostics
        self.secureInstall = secureInstall
        self.liveness = liveness
        self.underlayMTU = underlayMTU; appliedUnderlayMTU = underlayMTU
        self.underlay = underlay; self.clock = clock; self.steps = steps
        self.operationClock = operationClock ?? SuspendingDaemonClock()
        self.operationLog = operationLog ?? { DaemonDiagnostics.operationTiming($0) }
        let document = journal.snapshot()
        previousShutdownWasClean = document.cleanShutdownAt != nil
        lastProfileID = document.intent?.profileID
        generation = document.generation; intended = document.intent; settings = document.settings
        needsRecovery = document.intent != nil || !document.resources.isEmpty || document.pfPolicy != .disconnected || document
            .pfToken != nil
        health = HealthEvaluator(clock: ControllerHealthClock(clock: clock))
        if needsRecovery {
            snapshot.protection = .unknown
        }
        // An uninstall marker keeps this launch inert: no startup restore, and mutating requests refused (M05-T07).
        uninstallRun.fenced = document.uninstall != nil
        acceptingRequests = document.uninstall == nil
    }

    deinit { operation?.cancel(); eventTask?.cancel(); rotation.retryTask?.cancel(); captiveTask?.cancel(); onDemand.settleTask?.cancel() }

    public var status: TunnelStatus {
        snapshot
    }

    public var currentGeneration: Generation {
        generation
    }

    package static func pendingSecrets(_ bundle: consuming SecretBundle?) throws -> PendingDaemonSecrets? {
        switch consume bundle {
        case let .some(bundle): try PendingDaemonSecrets(bytes: bundle.wireBytes())
        case .none: nil
        }
    }

    /// `endedBy` is the receipt of the command that ends the intent; omitted, the end is newer than every received command.
    /// Lifecycle re-reservations of the current intent (a fence after an engine failure, a recovery repair) use this form;
    /// a control command reserves through `reserve(intent:deletingSecretsOf:by:)`.
    package func reserve(intent: TunnelIntent?, deletingSecretsOf: UUID? = nil, endedBy: UInt64? = nil) throws -> Generation {
        let next = try journal.allocate(intent: intent, deletingSecretsOf: deletingSecretsOf)
        if let intent, intent != intended {
            intentClaims &+= 1
        }
        if intent == nil {
            intentEndedAt = max(intentEndedAt, endedBy ?? admissions.latestReceipt)
        }
        lastProfileID = intent?.profileID ?? intended?.profileID ?? lastProfileID
        generation = next; intended = intent
        return next
    }

    package func awaitOperation(_ task: Task<Void, any Error>, generation: Generation) async throws {
        let slot = operationID
        do { try await boundedResult(task) }
        catch {
            if generation != self.generation {
                throw DaemonFailure.controllerSuperseded(by: self.generation)
            }
            if operationID == slot {
                operation = nil
            }
            try? await enforcePendingSecurePolicy()
            throw error
        }
        guard generation == self.generation else { throw DaemonFailure.controllerSuperseded(by: self.generation) }
        guard operationID == slot else { return }
        operation = nil
        try? await enforcePendingSecurePolicy()
        let events = pendingEvents; pendingEvents = []
        for (event, epoch) in events {
            await consume(event, generation: epoch)
        }
    }

    /// Auxiliary lifecycle work uses the same serial slot as start and stop.
    package func maintenance(_ body: @escaping @Sendable (isolated TunnelController, Generation) async throws -> Void) async throws {
        await drainLifecycle()
        guard !needsRecovery else { throw DaemonFailure.controllerRecoveryRequired }
        try requireNoUninstall()
        let current = generation
        let task = Task { [self] in
            do { try check(current); try requireNoUninstall(); try await body(self, current) }
            catch {
                // Under the uninstall fence no failure policy is applied: the uninstall clears pf after this drains (M05-T07).
                if current == generation, !uninstallFenced {
                    await maintenanceFailed(
                        generation: current,
                        reason: snapshot.recoveryFailureReason == .blockingPolicyFailed ? .blockingPolicyFailed : .reconciliationFailed,
                    )
                }
                throw error
            }
        }
        operation = task
        try await awaitOperation(task, generation: current)
    }

    package func checkExpected(_ expected: Generation?) throws {
        if let expected, expected != generation {
            throw DaemonFailure.controllerStaleGeneration(expected: expected, actual: generation)
        }
    }

    package func check(_ generation: Generation) throws {
        try Task.checkCancellation()
        guard !abandonedGenerations.contains(generation), generation == self.generation,
              journal.snapshot().generation == generation else { throw DaemonFailure.journalStaleGeneration }
    }

    package func checkpoint(_ step: DaemonStep, generation: Generation) async throws {
        try check(generation)
        try await steps.before(step, generation: generation)
        try check(generation)
        noteStepBegin(step)
        try entry(step, .willApply, generation: generation)
        if [.createEngine, .configureEngine, .engineUp, .configureInterface, .installRoutes, .installDNS].contains(step) {
            var resources = resource(generation); resources.attemptedSteps.insert(step)
            try updateResource(resources, generation: generation)
        }
    }

    /// One fixed-vocabulary line per step: its name and the milliseconds since the current operation began.
    package func noteStepBegin(_ step: DaemonStep) {
        lastStep = step
        let elapsed = operationStartedAt.map { operationClock.now - $0 } ?? .zero
        let milliseconds = elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000
        operationLog("step \(step.rawValue) begin +\(max(0, milliseconds))")
    }

    package func entry(_ step: DaemonStep, _ action: DaemonJournalEntry.Action, generation: Generation, recovery: Bool = false) throws {
        try journal.mutate(generation: recovery ? nil : generation) {
            $0.entries.append(DaemonJournalEntry(generation: generation, step: step, action: action))
        }
    }

    package func resource(_ generation: Generation) -> GenerationResources {
        journal.snapshot().resources.first { $0.generation == generation } ?? GenerationResources(generation: generation)
    }

    package func updateResource(_ value: GenerationResources, generation: Generation) throws {
        try journal.mutate(generation: generation) { document in
            var merged = value
            if let existing = document.resources.first(where: { $0.generation == value.generation }) {
                merged.attemptedSteps.formUnion(existing.attemptedSteps)
            }
            document.resources.removeAll { $0.generation == value.generation }; document.resources.append(merged)
        }
    }

    package func cancelBackgroundWork() {
        pendingEvents = []
        eventTask?.cancel(); eventTask = nil; rotation.retryTask?.cancel(); rotation.retryTask = nil; captiveTask?
            .cancel(); captiveTask = nil
    }
}

internal struct ControllerHealthClock: HealthClock {
    internal let clock: any DaemonClock
    internal var now: Duration {
        clock.now
    }
}

/// A wiped, explicitly copied payload can cross the Task closure's Copyable capture boundary.
package final class PendingDaemonSecrets: Sendable {
    private struct Storage: ~Copyable, Sendable { var bytes: SecretBytes }
    private let storage: Mutex<Storage>
    package init(bytes: consuming SecretBytes) throws {
        storage = Mutex(Storage(bytes: bytes))
    }

    package func wipe() {
        storage.withLock { value in
            value.bytes.withUnsafeMutableBytes { raw in
                _ = memset_s(raw.baseAddress, raw.count, 0, raw.count)
            }
        }
    }

    package func copy() throws -> SecretBytes {
        try storage.withLock { try SecretBytes(parsing: $0.bytes) }
    }
}
