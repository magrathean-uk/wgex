// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Root-owned registrations under `profiles/`: one `<uuid>.json` per profile with its `.repair` copy, purge tombstones
/// and the on-demand record.
public struct DirectoryProfileRepository: ProfileRepository {
    private let directory: StateDirectory
    public init(directory: StateDirectory) throws {
        self.directory = try directory.directory("profiles")
    }

    public func load(_ id: UUID) throws -> RegisteredProfile? {
        guard let bytes = try directory.read(id.uuidString + ".json") else { return nil }
        let result = try JSONDecoder().decode(RegisteredProfile.self, from: bytes)
        guard result.registration.profile.id == id else { throw DaemonFailure.stateInvalidDocument }
        return result
    }

    public func save(_ profile: RegisteredProfile) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(profile)
        try directory.replace(profile.registration.profile.id.uuidString + ".repair", with: bytes)
        try directory.replace(profile.registration.profile.id.uuidString + ".json", with: bytes)
    }

    public func remove(_ id: UUID) throws {
        try directory.remove(id.uuidString + ".json")
        try directory.remove(id.uuidString + ".repair")
    }

    /// Root-protected last accepted public registration permits owner-authenticated repair of an unreadable primary.
    public func repairRecord(_ id: UUID) throws -> RegisteredProfile? {
        guard let bytes = try directory.read(id.uuidString + ".repair") else { return nil }
        let record = try JSONDecoder().decode(RegisteredProfile.self, from: bytes)
        guard record.registration.profile.id == id else { throw DaemonFailure.stateInvalidDocument }
        return record
    }

    /// Decodes a readable registration first; an unreadable primary never erases its recorded owner.
    public func recordForRepair(_ id: UUID) throws -> RegisteredProfile? {
        do { return try load(id) }
        catch {
            guard let record = try repairRecord(id) else { throw error }
            return record
        }
    }

    /// Reads only root-protected identity metadata when a legacy profile cannot be decoded and has no repair copy.
    public func legacyRemovalOwner(_ id: UUID, after _: any Error) throws -> UInt32? {
        guard let bytes = try directory.read(id.uuidString + ".json") else { return nil }
        let identity = try JSONDecoder().decode(LegacyRemovalIdentity.self, from: bytes)
        guard identity.registration.profile.id == id else { throw DaemonFailure.stateInvalidDocument }
        return identity.ownerUID
    }

    public func otherRecords(excluding id: UUID) throws -> [RegisteredProfile] {
        try directory.filenames().compactMap { name in
            guard name.hasSuffix(".json"), let candidate = UUID(uuidString: String(name.dropLast(5))), candidate != id else { return nil }
            return try load(candidate)
        }
    }

    public func all() throws -> [RegisteredProfile] {
        try directory.filenames().compactMap { name in
            guard name.hasSuffix(".json"), let id = UUID(uuidString: String(name.dropLast(5))) else { return nil }
            return try load(id)
        }
    }
}

public extension DirectoryProfileRepository {
    /// Every file in `profiles/`: registrations, repair copies, tombstones and the on-demand record, decodable or not.
    func removeAll() throws {
        try directory.removeFiles()
    }

    func stagePurge(_ record: RegisteredProfile) throws {
        try directory.replace(record.registration.profile.id.uuidString + ".purge", with: JSONEncoder().encode(record))
    }

    func finishPurge(_ id: UUID) throws {
        try directory.remove(id.uuidString + ".purge")
    }

    func pendingPurges() throws -> [RegisteredProfile] {
        try directory.filenames().filter { $0.hasSuffix(".purge") }.map { name in
            guard let bytes = try directory.read(name) else { throw DaemonFailure.stateInvalidDocument }
            return try JSONDecoder().decode(RegisteredProfile.self, from: bytes)
        }
    }

    func loadOnDemandRecord() throws -> OnDemandRecord? {
        guard let bytes = try directory.read(Self.onDemandName) else { return nil }
        return try JSONDecoder().decode(OnDemandRecord.self, from: bytes)
    }

    func saveOnDemandRecord(_ record: OnDemandRecord) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try directory.replace(Self.onDemandName, with: encoder.encode(record))
    }

    /// Not a `.json` name, so profile enumeration never reads it as a registration.
    private static let onDemandName = "on-demand.state"
}

private struct LegacyRemovalIdentity: Decodable {
    struct Registration: Decodable { let profile: LegacyRemovalProfileIdentity }

    let ownerUID: UInt32
    let registration: Registration
}

private struct LegacyRemovalProfileIdentity: Decodable { let id: UUID }
