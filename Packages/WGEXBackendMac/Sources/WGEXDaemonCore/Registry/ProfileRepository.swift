// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

public protocol ProfileRepository: Sendable {
    func load(_ id: UUID) throws -> RegisteredProfile?
    func save(_ profile: RegisteredProfile) throws
    func remove(_ id: UUID) throws
    func all() throws -> [RegisteredProfile]
    /// Reads accepted repair metadata without losing the recorded owner.
    func recordForRepair(_ id: UUID) throws -> RegisteredProfile?
    /// Optional legacy metadata; unsupported repositories rethrow the original read failure.
    func legacyRemovalOwner(_ id: UUID, after failure: any Error) throws -> UInt32?
    /// Selects other registrations for boot-intent uniqueness.
    func otherRecords(excluding id: UUID) throws -> [RegisteredProfile]
    /// Persists a purge tombstone when the repository supports durable recovery.
    func stagePurge(_ record: RegisteredProfile) throws
    /// Removes a completed purge tombstone.
    func finishPurge(_ id: UUID) throws
    /// Lists durable tombstones awaiting cleanup.
    func pendingPurges() throws -> [RegisteredProfile]
    /// The durable on-demand record (ADR-030); nil when none was ever written. A record that cannot be decoded throws.
    func loadOnDemandRecord() throws -> OnDemandRecord?
    /// Replaces the on-demand record atomically.
    func saveOnDemandRecord(_ record: OnDemandRecord) throws
    /// Uninstall (M05-T07): every registration with its start-before-login flag, every purge tombstone and the on-demand
    /// record. Removing an empty repository succeeds.
    func removeAll() throws
}

public extension ProfileRepository {
    /// In-memory repositories use their ordinary record.
    func recordForRepair(_ id: UUID) throws -> RegisteredProfile? {
        try load(id)
    }

    /// A port without legacy repair metadata preserves its original read failure.
    func legacyRemovalOwner(_: UUID, after failure: any Error) throws -> UInt32? {
        throw failure
    }

    /// A repository without indexed selection uses the complete snapshot.
    func otherRecords(excluding _: UUID) throws -> [RegisteredProfile] {
        try all()
    }

    /// Nondurable repositories have no purge replay record.
    func stagePurge(_: RegisteredProfile) throws {}
    /// Nondurable repositories have no purge replay record.
    func finishPurge(_: UUID) throws {}
    /// Nondurable repositories have no purge replay record.
    func pendingPurges() throws -> [RegisteredProfile] {
        []
    }

    /// Record by record, for repositories without a directory of their own.
    func removeAll() throws {
        for record in try all() {
            try remove(record.registration.profile.id)
        }
        for record in try pendingPurges() {
            try finishPurge(record.registration.profile.id)
        }
        if try loadOnDemandRecord() != nil {
            try saveOnDemandRecord(OnDemandRecord())
        }
    }
}
