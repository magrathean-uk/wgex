// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy
import WGEXProfileStore

public struct RegisteredProfile: Codable, Sendable, Hashable {
    public let registration: DaemonProfile
    public let ownerUID: UInt32
    public let startBeforeLoginOverride: Bool?
    /// Absent in pre-CAS records, whose client-clock revision must be migrated.
    public let revisionIsDaemonOwned: Bool?
    public init(
        registration: DaemonProfile, ownerUID: UInt32, startBeforeLoginOverride: Bool? = nil, revisionIsDaemonOwned: Bool? = true,
    ) {
        self.revisionIsDaemonOwned = revisionIsDaemonOwned
        self.startBeforeLoginOverride = startBeforeLoginOverride
        self.registration = registration; self.ownerUID = ownerUID
    }
}

/// UID is supplied by the authenticated connection adapter, never deserialised from Request.
public actor ProfileRegistry {
    private let repository: any ProfileRepository
    private let secrets: any SecretStore
    private let bundles: any TunnelSecretStoring
    private let profileRegistered: @Sendable (TunnelProfile) -> Void
    private var dnsConfigured: [UUID: Bool] = [:]
    /// Every secret deletion of a two-phase purge still running, by id and token: two replays of one tombstone (a replay
    /// that outlived its watchdog, then the next) each run one, and a reinstall of the id waits for all of them, so a late
    /// deletion never lands after the reinstall publishes, and only for them.
    private var purging: [UUID: [UUID: Task<Void, any Error>]] = [:]
    /// Installs of each id waiting for its purge (host tests only read it).
    private var purgeWaiters: [UUID: Int] = [:]
    /// Passes of each id's waiting installs over its deletions, while any waits (host tests only read it).
    private var purgeDeletionsAwaited: [UUID: Int] = [:]
    private var ownerCache: [UUID: UInt32] = [:]
    private var ownersComplete = false
    /// Advanced by every committed mutation; the version of `armedSelection()` (ADR-030).
    private var commitVersion: UInt64 = 0
    /// The on-demand record as last read or written; nil until read, and again after a failed write.
    private var onDemandState: OnDemandRecord?
    /// Host tests only: runs in `armOnDemand` after its reads, right before its commit section.
    private var commitPause: (@Sendable () async -> Void)?
    private var purgePause: (@Sendable () async -> Void)?

    /// Installs an optional metadata fingerprint observer without a diagnostics package dependency.
    public init(
        repository: any ProfileRepository,
        secrets: any SecretStore,
        bundles: any TunnelSecretStoring,
        profileRegistered: @escaping @Sendable (TunnelProfile) -> Void = { _ in },
    ) {
        self.repository = repository; self.secrets = secrets; self.bundles = bundles; self.profileRegistered = profileRegistered
    }

    /// Uninstall (M05-T07): removes every registration, with its start-before-login flag, every purge tombstone and the
    /// on-demand record, and forgets what this actor cached of them. Idempotent, so a retry finishes a partial removal.
    internal func removeAllForUninstall() throws {
        try repository.removeAll()
        ownerCache = [:]; ownersComplete = true; dnsConfigured = [:]; onDemandState = nil; commitVersion &+= 1
    }

    /// Startup registers metadata before any global diagnostics can be collected.
    /// Loading each available bundle also invokes the secret-store fingerprint observer.
    public func registerInstalledProfiles() async throws {
        for record in try repository.all() {
            observeProfile(record.registration.profile)
            do { _ = try await bundles.loadBundle(profileID: record.registration.profile.id) }
            catch SecretStoreError.notFound { /* A profile may not have supplied secrets yet. */ }
        }
    }

    /// Allocates the next revision atomically in this actor. Identical content is an idempotent retry,
    /// even after a lost reply; only the dedicated authorised request changes persisted boot intent.
    @discardableResult
    public func installProfile(_ profile: TunnelProfile, expectedRevision: UInt64?, connectionUID: UInt32) async throws -> UInt64 {
        try await awaitPurge(profile.id)
        return try installUnlocked(profile, expectedRevision: expectedRevision, connectionUID: connectionUID)
    }

    /// A control command's install: after any purge of the id still deleting secrets, one commit section under its admission,
    /// ordered by receipt against every other write of the registration: an install that a newer removal or install of the
    /// id overtook while it waited reports a revision conflict instead of writing.
    @discardableResult
    internal func installProfile(
        _ profile: TunnelProfile, expectedRevision: UInt64?, connectionUID: UInt32, admission: borrowing Admission,
    ) async throws -> UInt64 {
        try await awaitPurge(profile.id)
        let revision = try admission.commitIfCurrent(.init(registrations: [profile.id])) {
            try installUnlocked(profile, expectedRevision: expectedRevision, connectionUID: connectionUID)
        }
        guard let revision else { throw DaemonFailure.registryRevisionConflict }
        return revision
    }

    private func installUnlocked(_ profile: TunnelProfile, expectedRevision: UInt64?, connectionUID: UInt32) throws -> UInt64 {
        let id = profile.id
        ownerCache.removeValue(forKey: id); ownersComplete = false
        var canonical = profile
        canonical.macOptions.startBeforeLogin = false
        try Self.validate(DaemonProfile(profile: canonical, revision: 0))
        let found = try recordForRepair(id)
        if let found {
            guard found.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        }
        let old = found.map { normalisedRevision($0) }
        if let old {
            var previous = old.registration.profile
            previous.macOptions.startBeforeLogin = false
            if previous == canonical {
                if old.startBeforeLoginOverride == true {
                    try requireUniqueBoot(excluding: id)
                }
                // Rewrite the repair copy too, without importing any boot flag.
                try saveInstalled(RegisteredProfile(
                    registration: DaemonProfile(profile: canonical, revision: old.registration.revision),
                    ownerUID: connectionUID,
                    startBeforeLoginOverride: old.startBeforeLoginOverride ?? false,
                ))
                commitVersion &+= 1
                observeProfile(canonical)
                return old.registration.revision
            }
            guard expectedRevision == old.registration.revision, old.registration.revision < UInt64.max else {
                throw DaemonFailure.registryRevisionConflict
            }
        } else if expectedRevision != nil {
            throw DaemonFailure.registryRevisionConflict
        }
        let revision = (old?.registration.revision ?? 0) + 1
        let bootOverride = old?.startBeforeLoginOverride ?? false
        if bootOverride {
            try requireUniqueBoot(excluding: id)
        }
        try saveInstalled(RegisteredProfile(
            registration: DaemonProfile(profile: canonical, revision: revision),
            ownerUID: connectionUID,
            startBeforeLoginOverride: bootOverride,
        ), fresh: old == nil)
        commitVersion &+= 1
        observeProfile(canonical)
        return revision
    }

    public func profile(_ id: UUID, connectionUID: UInt32) async throws -> DaemonProfile {
        guard let record = try repository.load(id) else { throw DaemonFailure.registryNotFound }
        guard record.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        try Self.validate(record.registration)
        observeProfile(record.registration.profile)
        return record.registration
    }

    /// Root-protected repair metadata preserves CAS after corruption without disclosing another owner's revision.
    public func installationRevision(_ id: UUID, connectionUID: UInt32) throws -> UInt64? {
        guard let record = try recordForRepair(id) else { return nil }
        guard record.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        return normalisedRevision(record).registration.revision
    }

    /// Section 5 permits an authenticated root caller to start an owner's profile; ownership itself never transfers.
    public func registrationForStart(_ id: UUID, connectionUID: UInt32) async throws -> RegisteredProfile {
        try registrationForStartUnlocked(id, connectionUID: connectionUID)
    }

    internal func registrationForStartUnlocked(_ id: UUID, connectionUID: UInt32) throws -> RegisteredProfile {
        guard let record = try repository.load(id) else { throw DaemonFailure.registryNotFound }
        guard connectionUID == 0 || record.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        try Self.validate(record.registration)
        observeProfile(record.registration.profile)
        return record
    }

    public func ownerUID(for id: UUID) throws -> UInt32? {
        if let owner = ownerCache[id] {
            return owner
        }
        do {
            let owner = try recordForRepair(id)?.ownerUID
            ownerCache[id] = owner
            return owner
        } catch {
            return try repository.legacyRemovalOwner(id, after: error)
        }
    }

    public func profileIDs(ownedBy uid: UInt32) throws -> Set<UUID> {
        if !ownersComplete {
            let records = try repository.all()
            ownerCache = Dictionary(uniqueKeysWithValues: records.map { ($0.registration.profile.id, $0.ownerUID) })
            ownersComplete = true
        }
        return Set(ownerCache.compactMap { $0.value == uid ? $0.key : nil })
    }

    public func setStartBeforeLogin(_ id: UUID, enabled: Bool, connectionUID: UInt32) async throws {
        try setStartBeforeLoginUnlocked(id, enabled: enabled, connectionUID: connectionUID)
    }

    /// A control command's start-before-login change, in one commit section under its admission, ordered by receipt per
    /// profile and registration incarnation: it lands only while no newer change of the flag and no newer install or removal
    /// of the profile committed. A stale enable fails superseded; a stale disable is skipped (the newer command decided).
    internal func setStartBeforeLogin(_ id: UUID, enabled: Bool, connectionUID: UInt32, admission: borrowing Admission) async throws {
        let scope = AdmissionLedger.Scope(boot: [id])
        let write = { try self.setStartBeforeLoginUnlocked(id, enabled: enabled, connectionUID: connectionUID) }
        if enabled {
            try admission.commit(scope, write)
        } else {
            _ = try admission.commitIfCurrent(scope, write)
        }
    }

    private func setStartBeforeLoginUnlocked(_ id: UUID, enabled: Bool, connectionUID: UInt32) throws {
        let record: RegisteredProfile
        if enabled {
            record = try registrationForStartUnlocked(id, connectionUID: connectionUID)
        } else {
            guard let found = try recordForRepair(id) else { throw DaemonFailure.registryNotFound }
            guard found.ownerUID == connectionUID || connectionUID == 0 else { throw DaemonFailure.registryNotOwner }
            record = found
        }
        if enabled {
            try requireUniqueBoot(excluding: id)
        }
        try repository.save(RegisteredProfile(
            registration: record.registration,
            ownerUID: record.ownerUID,
            startBeforeLoginOverride: enabled,
            revisionIsDaemonOwned: record.revisionIsDaemonOwned,
        ))
        commitVersion &+= 1
    }

    /// Read-only predicate; migration is persisted only by an accepted install within the controller barrier.
    public func requiresRevisionMigration(_ id: UUID, connectionUID: UInt32) throws -> Bool {
        guard let record = try recordForRepair(id) else { return false }
        guard record.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        return record.revisionIsDaemonOwned != true
    }

    /// Protection qualification never performs repository I/O or secret access.
    public func cachedDNSConfigured(_ id: UUID) -> Bool? {
        dnsConfigured[id]
    }

    private func observeProfile(_ profile: TunnelProfile) {
        dnsConfigured[profile.id] = !profile.interface.dns.isEmpty
        profileRegistered(profile)
    }

    private func normalisedRevision(_ record: RegisteredProfile) -> RegisteredProfile {
        guard record.revisionIsDaemonOwned != true else { return record }
        var profile = record.registration.profile; profile.macOptions.startBeforeLogin = false
        return RegisteredProfile(
            registration: DaemonProfile(profile: profile, revision: 1),
            ownerUID: record.ownerUID,
            startBeforeLoginOverride: record.startBeforeLoginOverride ?? false,
        )
    }

    private func recordForRepair(_ id: UUID) throws -> RegisteredProfile? {
        try repository.recordForRepair(id)
    }

    private func requireUniqueBoot(excluding id: UUID) throws {
        let others = try repository.otherRecords(excluding: id)
        guard !others.contains(where: {
            $0.registration.profile.id != id && ($0.startBeforeLoginOverride == true)
        }) else { throw DaemonFailure.registryMultipleBootProfiles }
    }

    public func bootIntent() throws -> TunnelIntent? {
        let profiles = try repository.all().filter { $0.startBeforeLoginOverride == true }
        guard profiles.count <= 1 else { throw DaemonFailure.registryMultipleBootProfiles }
        guard let record = profiles.first else { return nil }
        try Self.validate(record.registration)
        return TunnelIntent(profileID: record.registration.profile.id, ownerUID: record.ownerUID)
    }

    public static func validate(_ registration: DaemonProfile) throws {
        // Imported text belongs to the app; even a signed caller must not persist it in daemon state.
        guard registration.profile.original == nil,
              !registration.profile.validate().contains(where: { $0.severity == .error })
        else { throw DaemonFailure.registryInvalidProfile }
        let references = references(registration.profile).map(\.0)
        guard references.allSatisfy({
                  if case .daemonStore = $0 {
                      true
                  } else {
                      false
                  }
              }),
              Set(references).count == references.count else { throw DaemonFailure.registryInvalidSecretReference }
    }

    private static func references(_ profile: TunnelProfile) -> [(SecretRef, SecretID.Kind)] {
        [(profile.secrets.privateKey, .privateKey)] + profile.secrets.presharedKeys.values.map { ($0, .presharedKey) } +
            profile.secrets.carrierCredentials.values.map { ($0, .carrierCredential) }
    }
}

/// Removal and two-phase purge.
public extension ProfileRegistry {
    func removeProfile(_ id: UUID, purgeSecrets: Bool, connectionUID: UInt32) async throws {
        if let tombstone = try removeUnlocked(id, purgeSecrets: purgeSecrets, connectionUID: connectionUID) {
            try await deletePurged(tombstone)
        }
    }

    /// A control command's removal, purged in two phases: the tombstone and the removal commit in one section under the
    /// admission, ordered by receipt against every other write of the registration, then the secret deletion runs with
    /// nothing held and is idempotent (startup replays a tombstone left by a crash). A reinstall of the id waits for that
    /// deletion (`awaitPurge`).
    internal func removeProfile(_ id: UUID, purgeSecrets: Bool, connectionUID: UInt32, admission: borrowing Admission) async throws {
        let tombstone = try admission.commit(.init(registrations: [id])) {
            try removeUnlocked(id, purgeSecrets: purgeSecrets, connectionUID: connectionUID)
        }
        if let tombstone {
            try await deletePurged(tombstone)
        }
    }

    /// Phase one, synchronous: the durable tombstone, then the removal. Returns the tombstone a purge still has to delete.
    private func removeUnlocked(_ id: UUID, purgeSecrets: Bool, connectionUID: UInt32) throws -> RegisteredProfile? {
        ownerCache.removeValue(forKey: id); ownersComplete = false
        let found: RegisteredProfile?
        do { found = try recordForRepair(id) }
        catch {
            guard let owner = try repository.legacyRemovalOwner(id, after: error) else { throw error }
            guard owner == connectionUID else { throw DaemonFailure.registryNotOwner }
            // Unknown per-secret references cannot safely be purged. Owner removal without purge remains available.
            guard !purgeSecrets else { throw DaemonFailure.registryInvalidProfile }
            try repository.remove(id)
            commitVersion &+= 1
            dnsConfigured[id] = nil
            return nil
        }
        guard let record = found else { throw DaemonFailure.registryNotFound }
        guard record.ownerUID == connectionUID else { throw DaemonFailure.registryNotOwner }
        // Persist a tombstone before deleting the profile. Repeated purge completes after a crash (RT-06).
        let tombstone = RegisteredProfile(registration: record.registration, ownerUID: connectionUID)
        if purgeSecrets {
            try repository.stagePurge(tombstone)
        }
        try repository.remove(id)
        commitVersion &+= 1
        dnsConfigured[id] = nil
        return purgeSecrets ? tombstone : nil
    }

    /// Phase two: deletes the tombstone's secrets (idempotent) and then the tombstone. Holds nothing; only a reinstall of
    /// the same id waits for it.
    private func deletePurged(_ tombstone: RegisteredProfile) async throws {
        let id = tombstone.registration.profile.id
        let token = UUID()
        // The task leaves `purging` on this actor before it completes, so a waiter never finds a finished purge listed.
        let task = Task {
            defer { purgeEnded(id, token: token) }
            try await purge(tombstone)
            try repository.finishPurge(id)
        }
        purging[id, default: [:]][token] = task
        try await task.value
    }

    private func purgeEnded(_ id: UUID, token: UUID) {
        purging[id]?.removeValue(forKey: token)
        if purging[id]?.isEmpty == true {
            purging.removeValue(forKey: id)
        }
    }

    /// Waits for every deletion of `id`, and completes a purge a crash left behind, before the id is reused; rechecks all of
    /// them after each awaited one, its own included (a replay can start another). Only its own deletion's failure throws.
    private func awaitPurge(_ id: UUID) async throws {
        purgeWaiters[id, default: 0] += 1
        defer {
            purgeWaiters[id, default: 1] -= 1
            if purgeWaiters[id] == 0 {
                purgeWaiters.removeValue(forKey: id)
                purgeDeletionsAwaited.removeValue(forKey: id)
            }
        }
        while true {
            purgeDeletionsAwaited[id, default: 0] += 1
            if let pending = purging[id]?.values.first {
                _ = try? await pending.value
            } else if let leftover = try repository.pendingPurges().first(where: { $0.registration.profile.id == id }) {
                try await deletePurged(leftover)
            } else {
                return
            }
        }
    }

    func reconcilePurges() async throws {
        for record in try repository.pendingPurges() {
            try removePurged(record)
            try await deletePurged(record)
        }
    }

    /// Startup's purge replay under the reconciliation stage's admission: each removal commits in one section, then its
    /// idempotent deletion runs with nothing held. The replay completes a removal received before the crash, so it takes no
    /// registration watermark; instead the tombstones are read again before each removal, in the removal's registry turn, so
    /// one that a reinstall completed while an earlier deletion was awaited never removes the reinstalled registration.
    internal func reconcilePurges(admission: borrowing Admission) async throws {
        var replayed: Set<UUID> = []
        while let record = try repository.pendingPurges().first(where: { !replayed.contains($0.registration.profile.id) }) {
            replayed.insert(record.registration.profile.id)
            try admission.commit(.init()) { try removePurged(record) }
            try await deletePurged(record)
        }
    }

    private func removePurged(_ record: RegisteredProfile) throws {
        let id = record.registration.profile.id
        ownerCache.removeValue(forKey: id); ownersComplete = false
        try repository.remove(id)
        commitVersion &+= 1
    }

    private func purge(_ record: RegisteredProfile) async throws {
        if let purgePause {
            await purgePause()
        }
        let profile = record.registration.profile
        try await bundles.deleteBundle(profileID: profile.id)
        for (reference, kind) in Self.references(profile) {
            guard case let .daemonStore(id) = reference else { throw DaemonFailure.registryInvalidSecretReference }
            let secretID = SecretID(profileID: profile.id, kind: kind, id: id)
            if try await secrets.exists(secretID) {
                try await secrets.delete(secretID)
            }
        }
    }
}

/// ADR-030 selection: one durable record names the armed profile and the releases still owed; an install never arms.
public extension ProfileRegistry {
    /// Whether the policy compiles to at least one macOS rule; only such a profile can be armed.
    static func armable(_ profile: TunnelProfile) -> Bool {
        !OnDemandCompiler.compile(profile.onDemand, for: .macOS).rules.isEmpty
    }

    /// The armed registration, if any.
    func armedProfile() throws -> RegisteredProfile? {
        try selectionUnlocked().record
    }

    /// The armed registration with the version of the commit it reflects, read in one actor turn. Throws when the record
    /// cannot be read, so startup reports it instead of treating it as nothing armed.
    func armedSelection() throws -> ArmedSelection {
        try selectionUnlocked()
    }

    /// Whether `expected` is still the profile's registration: the same revision and interface key. Read in one actor turn,
    /// so it never observes an install half done.
    func isCurrentRegistration(_ expected: DaemonProfile) async -> Bool {
        guard let current = try? repository.load(expected.profile.id) else { return false }
        return current.registration.revision == expected.revision
            && current.registration.profile.interface.publicKey == expected.profile.interface.publicKey
    }

    /// The releases still owed, read from the durable record.
    func pendingReleases() throws -> [OnDemandRelease] {
        try onDemandRecordUnlocked().releases
    }

    /// Host tests only: holds every purge's secret deletion (phase two, nothing held), before its secret I/O.
    package func setPurgePause(_ pause: (@Sendable () async -> Void)?) {
        purgePause = pause
    }

    /// Host tests only: secret deletions of `id` still running.
    package func purgeDeletionsRunning(of id: UUID) -> Int {
        purging[id]?.count ?? 0
    }

    /// Host tests only: installs of `id` waiting for its purge.
    package func installsAwaitingPurge(of id: UUID) -> Int {
        purgeWaiters[id, default: 0]
    }

    /// Host tests only: passes of the waiting installs of `id` over its deletions so far; each pass awaits one, but the last.
    package func purgeDeletionsAwaited(of id: UUID) -> Int {
        purgeDeletionsAwaited[id, default: 0]
    }

    /// Host tests only: holds `armOnDemand` inside its commit section, after its mutation admission.
    package func setCommitPause(_ pause: (@Sendable () async -> Void)?) {
        commitPause = pause
    }

    internal func runCommitPause() async {
        if let commitPause {
            await commitPause()
        }
    }

    internal func selectionUnlocked() throws -> ArmedSelection {
        let armed = try onDemandRecordUnlocked().armed.flatMap { try repository.load($0) }
        return ArmedSelection(record: armed.flatMap { Self.armable($0.registration.profile) ? $0 : nil }, version: commitVersion)
    }

    internal func onDemandRecordUnlocked() throws -> OnDemandRecord {
        if let onDemandState {
            return onDemandState
        }
        let loaded = try repository.loadOnDemandRecord() ?? OnDemandRecord()
        onDemandState = loaded
        return loaded
    }

    internal func writeOnDemand(_ next: OnDemandRecord) throws {
        commitVersion &+= 1
        do { try repository.saveOnDemandRecord(next) }
        catch {
            onDemandState = nil // Read the record again: a failed replace leaves the old file or, at worst, the new one.
            throw error
        }
        onDemandState = next
    }

    /// An install never arms: one that leaves the armed profile without a macOS rule, or a fresh registration under an id
    /// the record still names, disarms it first in its own durable write, keeping only its secret retention to drop
    /// (ADR-030 section 6 rule 7), and restores the record if the registration write then fails.
    private func saveInstalled(_ record: RegisteredProfile, fresh: Bool = false) throws {
        let id = record.registration.profile.id
        guard let before = try? onDemandRecordUnlocked(), before.armed == id,
              fresh || !Self.armable(record.registration.profile)
        else {
            try repository.save(record)
            return
        }
        var next = before
        next.armed = nil
        next.release(id, stopsIntent: false)
        try writeOnDemand(next)
        do { try repository.save(record) }
        catch {
            try? writeOnDemand(before)
            throw error
        }
    }
}

internal extension ProfileRegistry {
    /// Uses a weak registry without changing the concrete adapter's preparation error.
    nonisolated func diagnosticsPreparation(unavailable: any Error) -> @Sendable () async throws -> Void {
        { [weak self] in
            guard let self else { throw unavailable }
            try await registerInstalledProfiles()
        }
    }
}
