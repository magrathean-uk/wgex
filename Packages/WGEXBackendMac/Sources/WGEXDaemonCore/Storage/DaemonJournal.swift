// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

/// One durable trial record. A process restart never trusts its relative awake-time deadline.
public struct CutoverRecord: Codable, Sendable, Hashable {
    /// Fences obsolete expiry tasks after a new trial.
    public let id: UUID
    /// Daemon launch that armed the trial; absent in legacy records, which require startup rollback.
    public let launchID: UUID?
    /// Trial target and authenticated owner, retained for recovery after intent is cleared.
    public let profileID: UUID
    /// Owner from the registry, never supplied in the request body.
    public let ownerUID: UInt32
    /// Public lifecycle state, including the advisory wall-clock deadline.
    public var state: CutoverState
    /// Relative SuspendingClock deadline; valid only in the arming process.
    public var awakeDeadlineSeconds: Int64
    /// Fractional component of the relative awake deadline.
    public var awakeDeadlineAttoseconds: Int64
    /// True until all rollback effects and their final journal write complete.
    public var rollbackPending = false
    /// Fixed step names; arbitrary system errors and secrets never enter the record.
    public var failures: [String] = []

    /// Creates a write-ahead record before tunnel intent or network effects.
    public init(profileID: UUID, ownerUID: UInt32, deadline: Date, awakeDeadline: Duration, launchID: UUID? = nil) {
        id = UUID(); self.launchID = launchID; self.profileID = profileID; self.ownerUID = ownerUID
        state = .armed(deadline: deadline)
        awakeDeadlineSeconds = awakeDeadline.components.seconds
        awakeDeadlineAttoseconds = awakeDeadline.components.attoseconds
    }

    package var awakeDeadline: Duration {
        Duration(secondsComponent: awakeDeadlineSeconds, attosecondsComponent: awakeDeadlineAttoseconds)
    }
}

public enum DaemonStep: String, Codable, Sendable, CaseIterable {
    case validateSecrets, blocking, resolve, allowEndpoints, createEngine, configureEngine, engineUp
    case configureInterface, installRoutes, installDNS, verify, connected, killStates, commit
    case stopBlocking, removeDNS, removeRoutes, engineDown, engineShutdown, finalPolicy, releaseToken, stopKillStates, deleteSecrets
    case reconcileBlocking, inspectReality, closeCaptive, applyIntents, openCaptive
    case rotateCandidate, retryBackoff
    /// Cutover rollback checkpoints, separate from ordinary blocking recovery.
    case cutoverIntent, cutoverBootIntent, cutoverComplete
}

public struct DaemonJournalEntry: Codable, Sendable, Hashable {
    public enum Action: String, Codable, Sendable { case willApply, didApply, undo, didUndo }
    public let generation: Generation
    public let step: DaemonStep
    public let action: Action
    public init(generation: Generation, step: DaemonStep, action: Action) {
        self.generation = generation; self.step = step; self.action = action
    }
}

/// Kernel identity of an interface the daemon fences (M1-18). A utun name alone can be reused by another application,
/// so the daemon's utun is also held by this process's kernel-control descriptor; a physical interface carries its
/// link-layer address. The kernel's ifi_lastchange is not part of it: XNU moves it in whole seconds on its own (guest
/// run 6: en0 about 0.2 s and utun4 about 5 s after protected, with no daemon change), so it is no identity token.
public struct TunnelIdentity: Codable, Sendable, Hashable {
    public let name: String
    public let interfaceIndex: UInt32
    /// The daemon's utun only: the open descriptor of the engine that created it. Absent for physical interfaces, in
    /// records written before M1-18, and whenever this process holds no descriptor reporting the name.
    public let descriptor: TunnelDescriptor?
    /// Physical interfaces only: the link-layer address, lowercase colon-separated hex; nil when there is none (utun).
    public let linkAddress: String?
    public init(name: String, interfaceIndex: UInt32, descriptor: TunnelDescriptor? = nil, linkAddress: String? = nil) {
        self.name = name; self.interfaceIndex = interfaceIndex; self.descriptor = descriptor; self.linkAddress = linkAddress
    }

    /// Source compatibility for fixtures outside this package written before M1-18 (WGEXUI ControllerShellFixture).
    /// The stamp is discarded; without a descriptor no tunnel fence admits the identity.
    @_disfavoredOverload
    public init(name: String, interfaceIndex: UInt32, creationID _: UUID) {
        self.init(name: name, interfaceIndex: interfaceIndex)
    }
}

/// The utun kernel-control descriptor this daemon process holds for one generation's engine (M1-18). The Go engine
/// creates the utun in this process (tun_kind 2) and owns the descriptor until shutdown; while it is open the kernel
/// cannot hand that utun unit to anyone else. Only the current process can hold it, so after a restart, or for another
/// generation whose engine reuses the descriptor number, the recorded value never matches again.
public struct TunnelDescriptor: Codable, Sendable, Hashable {
    public let fd: Int32
    public let generation: Generation
    public init(fd: Int32, generation: Generation) {
        self.fd = fd; self.generation = generation
    }
}

/// Who started the intended tunnel (ADR-030 section 8).
public enum IntentOrigin: String, Codable, Sendable, Hashable { case manual, onDemand }

public struct TunnelIntent: Codable, Sendable, Hashable {
    public let profileID: UUID
    public let ownerUID: UInt32
    /// Nil reads as `manual`; manual starts keep writing nil, so earlier journals and fixtures compare equal.
    public let origin: IntentOrigin?
    public init(profileID: UUID, ownerUID: UInt32, origin: IntentOrigin? = nil) {
        self.profileID = profileID; self.ownerUID = ownerUID; self.origin = origin == .manual ? nil : origin
    }

    /// The tunnel was started by an on-demand rule.
    public var startedOnDemand: Bool {
        origin == .onDemand
    }
}

/// Write-ahead identities include attempted operations, so a crash between effect and acknowledgement is recoverable.
public struct GenerationResources: Codable, Sendable, Hashable {
    /// Darwin net/route.h RTF_PROTO2; fixed in the on-disk schema, including on SDKs without routing headers.
    public static let protocol2RouteFlag: Int32 = 0x4000
    public let generation: Generation
    public var attemptedSteps: Set<DaemonStep> = []
    public var identity: TunnelIdentity?
    public var addresses: [IPAddressRange] = []
    public var routeFlags: Int32 = Self.protocol2RouteFlag
    public var routes: [RouteSpec] = []
    /// Separately fenced physical-interface route; absent in older checkpoints.
    public var canaryRoute: OwnedCanaryRoute?
    public var dns: DNSConfiguration?
    public var dnsKey: String?
    public init(generation: Generation) {
        self.generation = generation
    }
}

public struct CaptiveWindowRecord: Codable, Sendable, Hashable {
    public let expiresAtWall: Date
    /// A restart makes the continuous deadline undetermined; reconciliation closes the window.
    public let expiresAtContinuousSeconds: Int64
    public let expiresAtContinuousAttoseconds: Int64?
    public var continuousDeadline: Duration {
        Duration(secondsComponent: expiresAtContinuousSeconds, attosecondsComponent: expiresAtContinuousAttoseconds ?? 0)
    }

    public let wasExtended: Bool?
    public var extended: Bool {
        wasExtended ?? false
    }

    public init(
        expiresAtWall: Date, expiresAtContinuousSeconds: Int64, expiresAtContinuousAttoseconds: Int64 = 0, extended: Bool = false,
    ) {
        self.expiresAtWall = expiresAtWall; self.expiresAtContinuousSeconds = expiresAtContinuousSeconds
        self.expiresAtContinuousAttoseconds = expiresAtContinuousAttoseconds
        wasExtended = extended
    }
}

public struct DaemonJournalDocument: Codable, Sendable, Hashable {
    /// Version two requires append-log replay; version-one snapshots migrate before any new append.
    public var schemaVersion = 2
    public var generation = Generation(rawValue: 0)
    public var pendingSecretDeletions: Set<UUID> = []
    public var intent: TunnelIntent?
    public var loginSuspended: Bool?
    public var protectionOwnerUID: UInt32?
    public var settings = MacGlobalSettings.defaults
    public var pfPolicy: PacketFilterPolicy = .disconnected
    public var pfToken: String?
    /// Boot identity associated with the owned enable reference; nil for legacy journals.
    public var pfBootSession: UUID?
    /// Acquiring child PID, paired with token and boot identity.
    public var pfTokenPID: Int32?
    /// Durable before the child may execute pfctl -E.
    public var pfEnableAttempted: PFEnableAttempt?
    /// Set only after orderly shutdown policy completion, cleared at startup.
    public var cleanShutdownAt: Date?
    public var resources: [GenerationResources] = []
    public var captiveWindow: CaptiveWindowRecord?
    /// Absent in journals written before protocol 7.
    public var cutover: CutoverRecord?
    public var lastGoodAddresses: [String: [String]] = [:]
    public var entries: [DaemonJournalEntry] = []
    /// The uninstall marker (M05-T07): written first by `uninstall(purgeState:)` and kept after it completes, so the daemon
    /// stays inert at every later launch until a fresh secure install clears it. Absent in journals that never saw one.
    public var uninstall: UninstallRecord?
    public init() {}
}

/// The durable uninstall marker: the steps done so far, in order, so a retry or the next launch resumes after them.
public struct UninstallRecord: Codable, Sendable, Hashable {
    /// The journal and state directory go too; once asked for, a later uninstall never drops it.
    public var purgeState: Bool
    public var finished: [UninstallStep]
    /// Every step is done.
    public var completed: Bool

    public init(purgeState: Bool, finished: [UninstallStep] = [], completed: Bool = false) {
        self.purgeState = purgeState; self.finished = finished; self.completed = completed
    }

    /// The steps this uninstall runs, in order.
    public var steps: [UninstallStep] {
        UninstallStep.allCases.filter { $0 != .purgeState || purgeState }
    }

    /// The first step still owed; nil when every step is done.
    public var pendingStep: UninstallStep? {
        steps.first { !finished.contains($0) }
    }

    /// What `status` reports.
    public var progress: UninstallProgress {
        UninstallProgress(completed: completed, purgeState: purgeState, pendingStep: completed ? nil : pendingStep)
    }
}

/// Synchronous transactions keep allocation and generation validation atomic with publication.
public protocol DaemonJournalling: Sendable {
    func snapshot() -> DaemonJournalDocument
    func allocate(intent: TunnelIntent?, deletingSecretsOf: UUID?) throws -> Generation
    func mutate(generation: Generation?, _ body: (inout DaemonJournalDocument) throws -> Void) throws
    /// Uninstall with `purgeState` (M05-T07): removes every file of the state directory except the journal's own, keeping
    /// the directories the stores hold open. The caller then reduces the journal to the uninstall marker.
    func purgeStateFiles() throws
}

public final class DaemonJournal: DaemonJournalling {
    private let directory: StateDirectory
    private let state: Mutex<JournalState>
    private let transactions = NSLock()
    public init(directory: StateDirectory) throws {
        self.directory = directory
        let checkpoint: JournalCheckpoint
        let stored = try directory.read("journal.json")
        if let bytes = stored {
            checkpoint = try JSONDecoder().decode(JournalCheckpoint.self, from: bytes)
            guard [1, 2].contains(checkpoint.document.schemaVersion) else { throw DaemonFailure.journalInvalidVersion }
        } else {
            checkpoint = JournalCheckpoint(document: .init(), sequence: 0)
        }
        let bytes = try directory.read("journal.log") ?? Data()
        var restored = try JournalRecord.replay(bytes, checkpoint: checkpoint)
        if restored.logBytes < bytes.count {
            try directory.truncate("journal.log", to: restored.logBytes, durable: true)
        }
        guard [1, 2].contains(restored.document.schemaVersion) else { throw DaemonFailure.journalInvalidVersion }
        let migrate = stored == nil || checkpoint.document.schemaVersion == 1 || restored.document.schemaVersion == 1
        restored.document.schemaVersion = 2
        restored.document = Self.compact(restored.document)
        state = Mutex(restored)
        if migrate {
            restored.logBytes = try self.checkpoint(restored)
            state.withLock { $0 = restored }
        }
    }

    public func snapshot() -> DaemonJournalDocument {
        state.withLock { $0.document }
    }

    public func allocate(intent: TunnelIntent?, deletingSecretsOf: UUID?) throws -> Generation {
        transactions.lock(); defer { transactions.unlock() }
        var next = snapshot()
        guard next.generation.rawValue < UInt64.max else { throw DaemonFailure.journalExhausted }
        next.generation = Generation(rawValue: next.generation.rawValue + 1); next.intent = intent
        if let deletingSecretsOf {
            next.pendingSecretDeletions.insert(deletingSecretsOf)
        }
        if let intent {
            next.protectionOwnerUID = intent.ownerUID
            next.pendingSecretDeletions.remove(intent.profileID)
        }
        try commit(next)
        return next.generation
    }

    public func mutate(generation: Generation?, _ body: (inout DaemonJournalDocument) throws -> Void) throws {
        transactions.lock(); defer { transactions.unlock() }
        var next = snapshot()
        if let generation, generation != next.generation {
            throw DaemonFailure.journalStaleGeneration
        }
        try body(&next)
        try commit(next)
    }

    private func commit(_ value: DaemonJournalDocument) throws {
        let previous = state.withLock { $0 }
        guard !previous.failed else { throw DaemonFailure.stateInvalidDocument }
        guard value.schemaVersion == 2 else { throw DaemonFailure.journalInvalidVersion }
        let next = Self.compact(value)
        guard next != previous.document else { return }
        guard previous.sequence < UInt64.max else { throw DaemonFailure.journalExhausted }
        var updated = JournalState(document: next, sequence: previous.sequence + 1, logBytes: previous.logBytes)
        do {
            if previous.document.generation != next.generation || Self.requiresCheckpoint(previous.document, next) {
                // Allocation is a durable resource-ownership fence, not a history-only step. Cutover changes and
                // the clean-shutdown mark checkpoint too, so offline recovery can read journal.json without replay.
                updated.logBytes = try checkpoint(updated)
            } else {
                let frame = try JournalRecord.encode(
                    previous: previous.document,
                    value: value,
                    sequence: updated.sequence,
                    durable: Self.requiresDurability(previous.document, next),
                )
                if updated.logBytes + frame.count > 8 * 1024 * 1024 {
                    updated.logBytes = try checkpoint(previous)
                }
                try directory.append("journal.log", with: frame, durable: Self.requiresDurability(previous.document, next))
                updated.logBytes += frame.count
            }
        } catch {
            if let failure = error as? DaemonFailure, failure.kind == .stateRollbackFailed {
                state.withLock { $0.failed = true }
            }
            throw error
        }
        state.withLock { $0 = updated }
        if updated.logBytes > 65536, let remaining = try? checkpoint(updated) {
            state.withLock { $0.logBytes = remaining }
        }
    }

    private func checkpoint(_ value: JournalState) throws -> Int {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try directory.replace("journal.json", with: encoder.encode(JournalCheckpoint(
            document: value.document, sequence: value.sequence,
        )), durable: true)
        // The checkpoint sequence makes old records harmless if truncation cannot finish.
        do { try directory.truncate("journal.log", to: 0, durable: true); return 0 }
        catch { return value.logBytes }
    }

    public func purgeStateFiles() throws {
        transactions.lock(); defer { transactions.unlock() }
        try directory.removeFiles(keeping: ["journal.json", "journal.log"])
    }

    private static func requiresDurability(_ old: DaemonJournalDocument, _ next: DaemonJournalDocument) -> Bool {
        old.uninstall != next.uninstall || old.settings != next.settings || old.resources != next.resources
            || old.pfPolicy != next.pfPolicy || old.pfToken != next.pfToken
            || old.pfBootSession != next.pfBootSession || old.pfTokenPID != next.pfTokenPID || old.pfEnableAttempted != next
            .pfEnableAttempted || old.cutover != next.cutover
    }

    /// Rare transitions whose whole document must be readable from the checkpoint file alone (offline recovery).
    private static func requiresCheckpoint(_ old: DaemonJournalDocument, _ next: DaemonJournalDocument) -> Bool {
        old.cutover != next.cutover || (old.cleanShutdownAt == nil && next.cleanShutdownAt != nil) || old.uninstall != next.uninstall
    }

    package static func compact(_ value: DaemonJournalDocument) -> DaemonJournalDocument {
        var next = value
        let current = next.generation.rawValue
        next.entries = next.entries.filter { $0.generation.rawValue == current || (current > 0 && $0.generation.rawValue == current - 1) }
        var seen: Set<DaemonJournalEntry> = []
        next.entries = next.entries.reversed().filter { seen.insert($0).inserted }.reversed()
        return next
    }
}

public extension DaemonJournalling {
    func allocate(intent: TunnelIntent?) throws -> Generation {
        try allocate(intent: intent, deletingSecretsOf: nil)
    }

    /// A journal without a state directory cannot purge one; the purge step fails and stays owed.
    func purgeStateFiles() throws {
        throw DaemonFailure.uninstall(.purgeState)
    }
}
