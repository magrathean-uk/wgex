// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Persistable operation vocabulary. Execution, fault recovery and orphan collection are P2-09.
public struct JournalEntry: Codable, Sendable, Hashable, Identifiable {
    public enum Step: String, Codable, Sendable, CaseIterable {
        case stageSecret, writeProfile, installIntoBackend, verify, retireOldSecret
    }

    public enum Operation: String, Codable, Sendable { case install, rotateSecret, deleteProfile }
    public let id: UUID
    public var profileID: UUID
    public var operation: Operation
    public var completedSteps: [Step]
    public var oldSecret: SecretID?
    public var stagedSecret: SecretID?

    public init(
        id: UUID = UUID(), profileID: UUID, operation: Operation, completedSteps: [Step] = [],
        oldSecret: SecretID? = nil, stagedSecret: SecretID? = nil,
    ) {
        self.id = id; self.profileID = profileID; self.operation = operation; self.completedSteps = completedSteps
        self.oldSecret = oldSecret; self.stagedSecret = stagedSecret
    }
}

/// Document stored at `<container>/journal.json` by the P2-09 coordinator.
public struct Journal: Codable, Sendable, Hashable {
    public var schemaVersion: Int
    public var entries: [JournalEntry]

    public init(entries: [JournalEntry] = []) {
        schemaVersion = ProfileStoreSchema.journalVersion; self.entries = entries
    }
}

/// P2-09 seam: consult the journal before accepting operations at startup.
public protocol JournalReconciling: Sendable {
    func reconcileAtStartup() async throws
    func resume(_ entry: JournalEntry) async throws
    func collectOrphanedSecrets() async throws
}
