// SPDX-License-Identifier: MIT
// Explicit module access keeps mutable bookkeeping out of the package interface.
// swiftformat:disable redundantInternal
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

/// What a control command is, declared at admission (DEC-012, fable's check b). The kind decides, synchronously and before
/// the command's first await, which older uncommitted commands it supersedes, which hold it sets for its lifetime and whether
/// it is refused outright.
internal enum CommandKind: Sendable, Equatable {
    /// A start through the controller API that is not a manual connect (host tests, internal callers): no hold.
    case start
    /// `startIntent`: a manual connect (ADR-030 section 6 rules 4 and 5).
    case manualStart
    /// `startCutover`: a start whose trial arming and reservation run under this one admission.
    case cutover
    /// An automatic restart of the current intent (failed-start retry, captive-window restoration), derived from the
    /// admission that claimed the intent: it carries that receipt, never a fresh one.
    case restart
    /// The on-demand coordinator's start and stop of the armed profile; refused while the profile is held.
    case onDemandStart, onDemandStop
    /// A stop that is not a manual disconnect (update, logout, removal and recovery internals, cutover rollback).
    case stop
    /// `stop` or `stopCurrent` with `userRequested`: a manual disconnect (rule 3).
    case manualStop
    /// `disarmOnDemand` (rule 2) and a profile removal (rule 8).
    case disarm, remove
    /// `armOnDemand`.
    case arm
    /// A profile install.
    case install
    /// A start-before-login change: enabling it is a claim that a cutover arming revokes (ADR-030 section 7), disabling it
    /// is not.
    case bootEnable, bootDisable
    /// The release replay after reconciliation and the reconciliation stage itself.
    case replay, recovery

    internal var isStart: Bool {
        [.start, .manualStart, .cutover, .restart, .onDemandStart].contains(self)
    }

    internal var isStop: Bool {
        [.stop, .manualStop, .disarm, .remove, .onDemandStop].contains(self)
    }

    internal var isOnDemand: Bool {
        self == .onDemandStart || self == .onDemandStop
    }

    internal var isManual: Bool {
        self == .manualStart || self == .manualStop
    }

    internal var isBootIntent: Bool {
        self == .bootEnable || self == .bootDisable
    }

    /// Whether this command, admitted on `profile`, supersedes the older uncommitted `older` (on `olderProfile`).
    internal func supersedes(_ older: CommandKind, on olderProfile: UUID?, profile: UUID?) -> Bool {
        let same = profile != nil && olderProfile == profile
        // A stop of P wins over every older start, arm and on-demand action of P, wherever it waits.
        if isStop, same, older.isStart || older == .arm || older.isOnDemand {
            return true
        }
        switch self {
        // A manual connect disarms whatever is armed (rules 4 and 5): older arms and on-demand actions lose, any profile.
        case .manualStart: return older == .arm || older.isOnDemand
        // Arming moves the one selection: an older arm of any profile and every older on-demand action lose.
        case .arm: return older == .arm || older.isOnDemand
        // A manual disconnect disarms its profile (rule 3).
        case .manualStop: return same && older.isOnDemand
        default: return false
        }
    }
}

/// Synchronous admission state shared by the controller (admission, supersession, holds, reservation) and the registry
/// (commit), under one lock. Nothing here is held across an await: admission and commit are each one locked section.
internal final class AdmissionLedger: Sendable {
    internal struct Record: Sendable, Equatable {
        fileprivate let serial: UInt64
        internal let receipt: UInt64
        internal let kind: CommandKind
        internal let profileID: UUID?
    }

    /// Which watermarks a commit checks and advances. `claims` are profiles the commit makes newer claims on (an arm, a
    /// start's claim): they must not be fenced by a newer stop. `touches` are profiles whose on-demand state it changes.
    /// `registrations` are profiles whose registration it writes (an install, a removal); `boot` are profiles whose
    /// start-before-login flag it writes, which also must not be older than the registration's last write (the flag belongs
    /// to the registration incarnation the command read).
    internal struct Scope: Sendable {
        internal var claims: Set<UUID> = []
        internal var touches: Set<UUID> = []
        internal var registrations: Set<UUID> = []
        internal var boot: Set<UUID> = []
        internal var selection = false
        /// The command's decisive commit (an arm's selection): afterwards nothing supersedes or revokes it, so the work that
        /// follows from it (completing the releases it recorded) still runs under a live admission.
        internal var decisive = false
    }

    fileprivate struct Entry {
        let record: Record
        var revoked: DaemonFailure?
        /// Set by the decisive commit; a committed command is no longer superseded or revoked.
        var committed = false
        /// The profiles a manual command holds until it ends or is superseded (its own, and for a manual connect the armed one).
        var held: [UUID]
    }

    fileprivate struct State {
        var receipts: UInt64 = 0
        var serials: UInt64 = 0
        /// Uncommitted commands by serial, with the failure that revoked them, if any, and the profiles they hold.
        var live: [UInt64: Entry] = [:]
        /// Raised at admission by stop kinds: an older start, arm or on-demand action of the profile is dead.
        var fences: [UUID: UInt64] = [:]
        /// Raised at commit: the receipt of the newest command that committed on-demand state of the profile.
        var committed: [UUID: UInt64] = [:]
        /// Raised at commit by arms and manual connects: the newest command that committed the armed selection.
        var selectionCommitted: UInt64 = 0
        /// Raised at commit by installs and removals: the newest command that wrote the profile's registration.
        var registrationCommitted: [UUID: UInt64] = [:]
        /// Raised at commit by start-before-login changes: the newest command that wrote the profile's flag.
        var bootCommitted: [UUID: UInt64] = [:]
        /// Manual hold (ADR-030 section 6) for the lifetime of each manual command: on-demand kinds are refused.
        var holds: [UUID: Int] = [:]
        /// A removal in flight: starts, arms, installs, start-before-login changes and on-demand kinds are refused.
        var removing: [UUID: Int] = [:]
    }

    private let state = Mutex(State())

    internal static let superseded = DaemonFailure(code: .controllerSuperseded)
    /// What an ended admission reports: its command returned or threw (a watchdog expiry included), so nothing it left
    /// running may still commit or reserve.
    internal static let ended = superseded

    /// The newest receipt handed out; a command with a receipt at or below it was received before now.
    internal var latestReceipt: UInt64 {
        state.withLock { $0.receipts }
    }

    fileprivate func admit(
        _ kind: CommandKind, profile: UUID?, alsoHolding extra: UUID?, receipt inherited: UInt64? = nil,
    ) throws(DaemonFailure) -> Record {
        try state.withLock { (state: inout State) throws(DaemonFailure) -> Record in
            if let profile, let refusal = Self.refusal(state, kind, profile) {
                throw refusal
            }
            let receipt: UInt64
            if let inherited {
                receipt = inherited
                if let profile, state.fences[profile, default: 0] > inherited {
                    throw Self.superseded // A stop of the profile received after the parent: the derived command is dead.
                }
            } else {
                state.receipts &+= 1
                receipt = state.receipts
            }
            state.serials &+= 1
            let record = Record(serial: state.serials, receipt: receipt, kind: kind, profileID: profile)
            for (serial, entry) in state.live where entry.revoked == nil && !entry.committed && entry.record.receipt < receipt
                && kind.supersedes(entry.record.kind, on: entry.record.profileID, profile: profile)
            {
                state.live[serial]?.revoked = Self.superseded
                Self.release(&state, serial) // A superseded manual command holds nothing any more.
            }
            if let profile, kind.isStop, inherited == nil {
                state.fences[profile] = max(state.fences[profile, default: 0], receipt)
            }
            let held = kind.isManual ? [profile, extra].compactMap(\.self) : []
            for profile in held {
                state.holds[profile, default: 0] += 1
            }
            if kind == .remove, let profile {
                state.removing[profile, default: 0] += 1
            }
            state.live[record.serial] = Entry(record: record, held: held)
            return record
        }
    }

    /// Refusal at admission: an on-demand action of a profile a manual command holds; a start, arm or start-before-login
    /// change of a profile being removed finds no profile, and an install of it is busy.
    private static func refusal(_ state: State, _ kind: CommandKind, _ profile: UUID) -> DaemonFailure? {
        if kind.isOnDemand, state.holds[profile, default: 0] > 0 {
            return superseded
        }
        guard state.removing[profile, default: 0] > 0 else { return nil }
        if kind == .install {
            return DaemonFailure.registryBusy
        }
        return kind.isStart || kind.isOnDemand || kind == .arm || kind.isBootIntent ? DaemonFailure.registryNotFound : nil
    }

    private static func release(_ state: inout State, _ serial: UInt64) {
        guard let held = state.live[serial]?.held, !held.isEmpty else { return }
        state.live[serial]?.held = []
        for profile in held {
            state.holds[profile, default: 1] -= 1
            if state.holds[profile] == 0 {
                state.holds.removeValue(forKey: profile)
            }
        }
    }

    /// Whether a manual command in flight holds `profile`: on-demand actions and release stops of it wait for that command,
    /// and its secrets are retained until it ends.
    internal func isHeld(_ profile: UUID) -> Bool {
        state.withLock { $0.holds[profile, default: 0] > 0 }
    }

    fileprivate func end(_ record: Record) {
        state.withLock { state in
            Self.release(&state, record.serial)
            state.live.removeValue(forKey: record.serial)
            if record.kind == .remove, let profile = record.profileID {
                state.removing[profile, default: 1] -= 1
                if state.removing[profile] == 0 {
                    state.removing.removeValue(forKey: profile)
                }
            }
        }
    }

    /// The failure that revoked `record`, or nil while it may still commit. A record no longer live has ended: it is dead.
    fileprivate func revocation(_ record: Record) -> DaemonFailure? {
        state.withLock { Self.revocation($0, record) }
    }

    private static func revocation(_ state: State, _ record: Record) -> DaemonFailure? {
        guard let entry = state.live[record.serial] else { return ended }
        return entry.revoked
    }

    /// Marks `record` committed (a reservation that claimed an intent): nothing supersedes or revokes it afterwards.
    fileprivate func markCommitted(_ record: Record) {
        state.withLock { $0.live[record.serial]?.committed = true }
    }

    /// Whether a start-like claim on `profile` by `record` is fenced by a stop received after it.
    fileprivate func fenced(_ record: Record, profile: UUID) -> Bool {
        state.withLock { $0.fences[profile, default: 0] > record.receipt }
    }

    /// Revokes every live command of `kinds` (recovery, a cutover and shutdown revoke arms and start-before-login enables
    /// that have not committed).
    internal func revokeAll(_ kinds: Set<CommandKind>, _ failure: DaemonFailure) {
        state.withLock { state in
            for (serial, entry) in state.live where entry.revoked == nil && !entry.committed && kinds.contains(entry.record.kind) {
                state.live[serial]?.revoked = failure
            }
        }
    }

    private static func overtaken(_ state: State, _ receipt: UInt64, _ scope: Scope) -> Bool {
        scope.claims.union(scope.touches).contains { state.committed[$0, default: 0] > receipt }
            || (scope.selection && state.selectionCommitted > receipt)
            || scope.registrations.union(scope.boot).contains { state.registrationCommitted[$0, default: 0] > receipt }
            || scope.boot.contains { state.bootCommitted[$0, default: 0] > receipt }
    }

    /// Whether a commit of `scope` would land now (not revoked, not fenced, not overtaken); the caller commits in the same
    /// registry turn, so only a revocation or a fence can come between, and the commit re-checks both.
    fileprivate func passes(_ record: Record, _ scope: Scope) -> Bool {
        state.withLock { state in
            Self.revocation(state, record) == nil
                && !scope.claims.contains { state.fences[$0, default: 0] > record.receipt }
                && !Self.overtaken(state, record.receipt, scope)
        }
    }

    /// The compare-and-set commit: in one locked section, `record` must be live (neither revoked nor ended), no profile it
    /// claims may be fenced by a newer stop, and no newer command may have committed the profiles it touches, their
    /// registrations or start-before-login flags, or the selection. Then `body` writes and the watermarks move to the
    /// receipt, so commits land in receipt order. A stale commit is skipped (nil) when `skipIfStale`, else it throws
    /// superseded; a dead one always throws.
    fileprivate func commit<R>(
        _ record: Record, _ scope: Scope, skipIfStale: Bool, _ body: () throws -> R,
    ) throws -> R? {
        try state.withLock { state in
            if let dead = Self.revocation(state, record) {
                throw dead
            }
            let receipt = record.receipt
            // A claim fenced by a newer stop of its profile belongs to a dead command: it always fails.
            if scope.claims.contains(where: { state.fences[$0, default: 0] > receipt }) {
                throw Self.superseded
            }
            if Self.overtaken(state, receipt, scope) {
                if skipIfStale {
                    return nil
                }
                throw Self.superseded
            }
            let result = try body()
            if scope.decisive {
                state.live[record.serial]?.committed = true
            }
            for profile in scope.claims.union(scope.touches) {
                state.committed[profile] = max(state.committed[profile, default: 0], receipt)
            }
            if scope.selection {
                state.selectionCommitted = max(state.selectionCommitted, receipt)
            }
            for profile in scope.registrations {
                state.registrationCommitted[profile] = max(state.registrationCommitted[profile, default: 0], receipt)
            }
            for profile in scope.boot {
                state.bootCommitted[profile] = max(state.bootCommitted[profile, default: 0], receipt)
            }
            return result
        }
    }
}

/// A control command's admission: non-copyable, taken synchronously before the command's first await (`withCommand`), and
/// the only key to registry mutation and to reservation. Derived commands borrow the parent's admission, or rebuild one from
/// the parent's lineage (`AdmissionLineage`) inside an escaping closure or later (a retry of the intent the parent claimed);
/// they never take a fresh receipt.
internal struct Admission: ~Copyable, Sendable {
    fileprivate let ledger: AdmissionLedger
    fileprivate let record: AdmissionLedger.Record

    fileprivate init(ledger: AdmissionLedger, record: AdmissionLedger.Record) {
        self.ledger = ledger; self.record = record
    }

    internal var receipt: UInt64 {
        record.receipt
    }

    internal var kind: CommandKind {
        record.kind
    }

    internal var lineage: AdmissionLineage {
        AdmissionLineage(ledger: ledger, record: record)
    }

    /// Throws the failure that revoked this admission (a newer command superseded it, or recovery, a cutover or shutdown
    /// began), so a dead admission reports superseded at its next check.
    internal func requireLive() throws(DaemonFailure) {
        if let failure = ledger.revocation(record) {
            throw failure
        }
    }

    /// The command's decisive commit happened outside the registry (a reservation that claimed an intent).
    internal func markCommitted() {
        ledger.markCommitted(record)
    }

    /// Whether a start-like claim on `profile` is dead: revoked, or fenced by a stop received after it.
    internal func isFenced(claiming profile: UUID) -> Bool {
        ledger.revocation(record) != nil || ledger.fenced(record, profile: profile)
    }

    /// Whether a commit of `scope` would land now (`AdmissionLedger.passes`).
    internal func passes(_ scope: AdmissionLedger.Scope) -> Bool {
        ledger.passes(record, scope)
    }

    /// The registry's commit section (see `AdmissionLedger.commit`).
    internal func commit<R>(_ scope: AdmissionLedger.Scope, _ body: () throws -> R) throws -> R {
        guard let result = try ledger.commit(record, scope, skipIfStale: false, body) else { throw AdmissionLedger.superseded }
        return result
    }

    /// As `commit`, but a commit a newer command overtook is skipped (nil) instead of failing: a release, a disarm or a
    /// claim's discharge that a newer command already decided.
    internal func commitIfCurrent<R>(_ scope: AdmissionLedger.Scope, _ body: () throws -> R) throws -> R? {
        try ledger.commit(record, scope, skipIfStale: true, body)
    }
}

/// The copyable identity of an admitted command, from which only the controller rebuilds an `Admission` for the same command
/// (an escaping closure of that command) or for a command derived from it (`TunnelController.deriveAdmission`).
internal struct AdmissionLineage: Sendable, Equatable {
    fileprivate let ledger: AdmissionLedger
    fileprivate let record: AdmissionLedger.Record

    internal var receipt: UInt64 {
        record.receipt
    }

    internal static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.ledger === rhs.ledger && lhs.record == rhs.record
    }
}

internal extension TunnelController {
    /// Admits a control command synchronously: refusal, supersession and holds by `kind` (see `CommandKind.supersedes`),
    /// then the receipt. An input advances the on-demand epoch and holds evaluation until the command ends. Only the
    /// lifetime wrappers below call it, so every admission is ended by `run`.
    private func admit(_ kind: CommandKind, profile: UUID?, input: Bool) throws(DaemonFailure) -> Admission {
        let extra = kind == .manualStart ? onDemand.armed?.profileID : nil
        let record = try admissions.admit(kind, profile: profile, alsoHolding: extra)
        if input {
            onDemandInputReceived()
        }
        controlReceipts = admissions.latestReceipt
        return Admission(ledger: admissions, record: record)
    }

    /// Ends an admitted command once: its holds go, and an input lets evaluation decide again. Anything the command left
    /// running is dead from here on: it can neither reserve nor commit (`AdmissionLedger.ended`).
    private func end(_ admission: borrowing Admission, input: Bool) {
        admissions.end(admission.record)
        if input {
            onDemandInputApplied(.inputSettled)
        }
    }

    /// The one admission lifetime: the body runs under the admission, which ends when the body returns or throws.
    private func run<R>(
        _ admission: consuming Admission, input: Bool, _ body: (borrowing Admission) async throws -> R,
    ) async throws -> R {
        defer { end(admission, input: input) }
        return try await body(admission)
    }

    /// Every entry point runs its body through this wrapper: the admission is taken before the body's first await and ended
    /// when the body returns or throws. Nothing is held across the body's awaits.
    @discardableResult
    func withCommand<R>(
        _ kind: CommandKind, profile: UUID?, input: Bool = true, _ body: (borrowing Admission) async throws -> R,
    ) async throws -> R {
        try await run(admit(kind, profile: profile, input: input), input: input, body)
    }

    /// `withCommand` for a body that runs in a task (the release replay): the admission is taken now, synchronously, before
    /// the task exists and before anything is read; it moves into the task once and ends through the same `run`. `finally`
    /// runs after it ended. Nil when the command is refused at admission.
    func scheduleCommand(
        _ kind: CommandKind, profile: UUID?, input: Bool = true,
        _ body: @escaping @Sendable (isolated TunnelController, borrowing Admission) async -> Void,
        finally: @escaping @Sendable (isolated TunnelController) async -> Void = { _ in },
    ) -> Task<Void, Never>? {
        guard let admission = try? admit(kind, profile: profile, input: input) else { return nil }
        let carrier = AdmissionCarrier(admission)
        return Task { [weak self] in
            await self?.runScheduled(carrier, input: input, body, finally: finally)
        }
    }

    private func runScheduled(
        _ carrier: AdmissionCarrier, input: Bool, _ body: @Sendable (isolated TunnelController, borrowing Admission) async -> Void,
        finally: @Sendable (isolated TunnelController) async -> Void,
    ) async {
        if let admission = carrier.take() {
            _ = try? await run(admission, input: input) { admission in await body(self, admission) }
        }
        await finally(self)
    }

    /// `withCommand` for a command derived from `parent` after the parent ended (`deriveAdmission`): the same lifetime, no
    /// input.
    func withDerivedCommand<R>(
        from parent: AdmissionLineage, kind: CommandKind, profile: UUID, _ body: (borrowing Admission) async throws -> R,
    ) async throws -> R {
        try await run(deriveAdmission(from: parent, kind: kind, profile: profile), input: false, body)
    }

    /// The same command's admission inside one of its escaping closures (a recovery repair, a maintenance body). Once the
    /// command has ended, the rebuilt admission is dead: a closure that outlives its command (a repair past its watchdog)
    /// can neither reserve nor commit.
    func readmit(_ lineage: AdmissionLineage) -> Admission {
        Admission(ledger: lineage.ledger, record: lineage.record)
    }

    /// A command derived from `parent` after the parent ended (a failed-start retry, a captive-window restoration): it keeps
    /// the parent's receipt, is born dead when a stop of the profile was received after the parent, and is superseded like
    /// any start. Only `withDerivedCommand` calls it.
    private func deriveAdmission(
        from parent: AdmissionLineage, kind: CommandKind, profile: UUID,
    ) throws(DaemonFailure) -> Admission {
        let record = try admissions.admit(kind, profile: profile, alsoHolding: nil, receipt: parent.receipt)
        return Admission(ledger: admissions, record: record)
    }

    /// A control command's reservation, the intent's compare-and-set commit, with no suspension after its checks: the admission
    /// is live, no newer reservation claimed an intent, and a claim is neither fenced by a newer stop of its profile nor older
    /// than the last end of the intent. A claim records the receipt and the admission's lineage.
    func reserve(intent: TunnelIntent?, deletingSecretsOf: UUID? = nil, by admission: borrowing Admission) throws -> Generation {
        try admission.requireLive()
        guard newestStartAt <= admission.receipt else { throw DaemonFailure.controllerSuperseded(by: generation) }
        if let intent {
            guard intentEndedAt < admission.receipt, !admission.isFenced(claiming: intent.profileID) else {
                throw DaemonFailure.controllerSuperseded(by: generation)
            }
        }
        let next = try reserve(intent: intent, deletingSecretsOf: deletingSecretsOf, endedBy: admission.receipt)
        if intent != nil {
            intentClaims &+= 1 // Even an equal intent is a newer claim: an older cleanup must not stop it.
            newestStartAt = max(newestStartAt, admission.receipt)
            intentLineage = admission.lineage
            admission.markCommitted()
        }
        return next
    }

    /// A stop that keeps the intent (an update, a failure, a logout, a shutdown, a takeover): the same receipt, liveness and
    /// newest-start checks as every command reservation, with no suspension after them, so a stop received before a newer
    /// start never cancels it; the intent, its claim count and its lineage stay as they are, and the reservation records the
    /// stop's receipt.
    func reserve(retaining intent: TunnelIntent?, deletingSecretsOf: UUID?, by admission: borrowing Admission) throws -> Generation {
        try admission.requireLive()
        guard newestStartAt <= admission.receipt else { throw DaemonFailure.controllerSuperseded(by: generation) }
        return try reserve(intent: intent, deletingSecretsOf: deletingSecretsOf, endedBy: admission.receipt)
    }

    /// Recovery, a cutover arming or rollback and shutdown revoke every arm and every start-before-login enable that has not
    /// committed yet; the revocation is checked inside the registry's commit section, so a revoked enable never writes.
    func revokeCommitAdmissions(_ failure: DaemonFailure) {
        admissions.revokeAll([.arm, .bootEnable], failure)
    }
}

/// Moves an admission into its scheduled task once (`scheduleCommand`).
private final class AdmissionCarrier: Sendable {
    private let slot: Mutex<Admission?>

    init(_ admission: consuming Admission) {
        slot = Mutex(Optional(admission))
    }

    func take() -> Admission? {
        slot.withLock { $0.take() }
    }
}
