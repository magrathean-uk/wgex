// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import WGEXCore

public enum ProfileStoreError: Error, Sendable, Equatable {
    case notFound, invalidDocument, unsupportedVersion(Int), invalidMigration
    case system(Int32)
}

/// Serialises writers within this store instance. Use one instance per container.
/// The operation journal's cross-backend transaction and reconciliation belong to P2-09.
public actor ProfileStore {
    public enum WritePoint: Sendable { case temporaryFileSynced, beforeMigrationReadBack }
    public typealias WriteHook = @Sendable (WritePoint, URL) throws -> Void

    /// Hard bound applied before decoding any profile document.
    public static let maximumProfileBytes = 1_048_576
    private var reportedQuarantine = Set<UUID>()
    private var pendingQuarantine: [UUID] = []

    private let container: URL
    private let migrations: [Migration]
    private let hook: WriteHook?
    /// Whether a document without an address or a peer loads (DEC-088). Only the Mac app's persistence sets it; every other
    /// owner keeps the full `validate()` gate and quarantines such a document as before.
    private let admitsIncomplete: Bool

    public init(
        container: URL, migrations: [Migration] = Migration.standard, writeHook: WriteHook? = nil, admitsIncomplete: Bool = false,
    ) {
        self.container = container; self.migrations = migrations; hook = writeHook; self.admitsIncomplete = admitsIncomplete
    }

    /// Loads each valid profile independently, recording unreadable identities for the quarantine report.
    public func list() throws -> [TunnelProfile] {
        let directory = container.appendingPathComponent("profiles", isDirectory: true)
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        let ids = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }.compactMap { UUID(uuidString: $0.deletingPathExtension().lastPathComponent) }
            .sorted { $0.uuidString < $1.uuidString }
        return ids.compactMap { id in
            do { return try load(id) }
            catch {
                if reportedQuarantine.insert(id).inserted {
                    pendingQuarantine.append(id)
                }
                return nil
            }
        }
    }

    /// Drains newly quarantined identities once per store instance; source files remain available for recovery.
    public func takeQuarantinedProfiles() -> [UUID] {
        defer { pendingQuarantine = [] }
        return pendingQuarantine
    }

    /// Loads and validates a bounded document, migrating only recognised envelope versions.
    public func load(_ id: UUID) throws -> TunnelProfile {
        let url = profileURL(id)
        var document = try readDocument(url)
        guard document.profile.schemaVersion == TunnelProfile.currentSchemaVersion else {
            throw ConfigurationError.unsupportedSchema(document.profile.schemaVersion)
        }
        guard document.profile.id == id else { throw ProfileStoreError.invalidDocument }
        let original = document
        guard (1 ... ProfileDocument.currentSchemaVersion).contains(document.schemaVersion) else {
            throw ProfileStoreError.unsupportedVersion(document.schemaVersion)
        }
        while document.schemaVersion < ProfileDocument.currentSchemaVersion {
            let steps = migrations.filter { $0.fromVersion == document.schemaVersion }
            guard steps.count == 1, let migration = steps.first else { throw ProfileStoreError.invalidMigration }
            document = try migration.apply(document)
        }
        guard document.profile.schemaVersion == TunnelProfile.currentSchemaVersion else {
            throw ProfileStoreError.unsupportedVersion(document.profile.schemaVersion)
        }
        let issues = admitsIncomplete ? document.profile.storageDiagnostics() : document.profile.validate()
        guard !issues.contains(where: { $0.severity == .error }) else {
            throw ProfileStoreError.invalidDocument
        }
        if document != original {
            let expected = document
            try atomicWrite(document.encoded(), to: url) { candidate in
                try self.hook?(.beforeMigrationReadBack, candidate)
                let readBack = try JSONDecoder().decode(ProfileDocument.self, from: Data(contentsOf: candidate))
                guard readBack == expected else { throw ProfileStoreError.invalidDocument }
            }
        }
        return document.profile
    }

    public func save(_ profile: TunnelProfile) throws {
        try atomicWrite(ProfileDocument(profile: profile).encoded(), to: profileURL(profile.id))
    }

    /// Removes only the public document. Secret retirement is ordered separately by P2-09.
    public func delete(_ id: UUID) throws {
        let url = profileURL(id)
        guard FileManager.default.fileExists(atPath: url.path) else { throw ProfileStoreError.notFound }
        try FileManager.default.removeItem(at: url)
    }

    public func loadSettings() throws -> SettingsDocument {
        let url = container.appendingPathComponent("settings.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return SettingsDocument() }
        let document = try JSONDecoder().decode(SettingsDocument.self, from: Data(contentsOf: url))
        guard document.schemaVersion == SettingsDocument.currentSchemaVersion else {
            throw ProfileStoreError.unsupportedVersion(document.schemaVersion)
        }
        return document
    }

    public func saveSettings(_ settings: SettingsDocument) throws {
        guard settings.schemaVersion == SettingsDocument.currentSchemaVersion else {
            throw ProfileStoreError.unsupportedVersion(settings.schemaVersion)
        }
        try atomicWrite(DocumentCodec.encode(settings), to: container.appendingPathComponent("settings.json"))
    }

    private func readDocument(_ url: URL) throws -> ProfileDocument {
        guard FileManager.default.fileExists(atPath: url.path) else { throw ProfileStoreError.notFound }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let data = try file.read(upToCount: Self.maximumProfileBytes + 1) ?? Data()
        guard data.count <= Self.maximumProfileBytes else { throw ProfileStoreError.invalidDocument }
        let decoded: ProfileDocument
        do { decoded = try JSONDecoder().decode(ProfileDocument.self, from: data) }
        catch { throw ProfileStoreError.invalidDocument }
        return decoded
    }

    private func profileURL(_ id: UUID) -> URL {
        container.appendingPathComponent("profiles", isDirectory: true).appendingPathComponent(id.uuidString + ".json")
    }

    private func atomicWrite(_ data: Data, to destination: URL, validate: ((URL) throws -> Void)? = nil) throws {
        let directory = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let candidate = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
        defer { try? FileManager.default.removeItem(at: candidate) }
        let descriptor = open(candidate.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw ProfileStoreError.system(errno) }
        do {
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(descriptor, bytes.baseAddress?.advanced(by: offset), bytes.count - offset)
                    if count < 0, errno == EINTR {
                        continue
                    }
                    guard count > 0 else { throw ProfileStoreError.system(errno) }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0 else { throw ProfileStoreError.system(errno) }
        } catch { close(descriptor); throw error }
        guard close(descriptor) == 0 else { throw ProfileStoreError.system(errno) }
        try hook?(.temporaryFileSynced, candidate)
        try validate?(candidate)
        guard rename(candidate.path, destination.path) == 0 else { throw ProfileStoreError.system(errno) }
    }
}
