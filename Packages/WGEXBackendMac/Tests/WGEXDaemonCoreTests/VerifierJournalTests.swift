// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct VerifierJournalTests {
    @Test(arguments: [0, 1, 2])
    func `an incomplete final entry preserves the last durable policy`(corruption: Int) throws {
        let harness = try ControllerHarness()
        let generation = try harness.journal.allocate(intent: nil)
        try harness.journal.mutate(generation: generation) { $0.pfPolicy = .lockdown }
        let durable = harness.journal.snapshot()
        let prefix = try #require(try harness.directory.read("journal.log"))
        var tail: Data
        if corruption == 0 {
            tail = prefix + Data(repeating: 0, count: 4)
        } else {
            try harness.journal.mutate(generation: generation) {
                $0.entries.append(.init(generation: generation, step: .commit, action: .didApply))
            }
            tail = try #require(try harness.directory.read("journal.log"))
            if corruption == 1 {
                tail[tail.count - 1] ^= 1
            } else {
                tail[prefix.count + 4] = 255
            }
        }
        try harness.directory.replace("journal.log", with: tail)
        let recovered = try DaemonJournal(directory: harness.directory)
        #expect(recovered.snapshot() == durable)
        #expect(try harness.directory.read("journal.log") == prefix)
    }

    @Test
    func `global settings changes are durable`() throws {
        let harness = try ControllerHarness(), observations = Mutex<[StateDirectoryWrite]>([])
        let directory = try StateDirectory(root: harness.root, observingWrites: { value in observations.withLock { $0.append(value) } })
        let journal = try DaemonJournal(directory: directory)
        let generation = try journal.allocate(intent: nil)
        observations.withLock { $0 = [] }
        try journal.mutate(generation: generation) { $0.settings.allowLAN.toggle() }
        #expect(observations.withLock { $0.count == 1 && $0[0].durable })
        #expect(try DaemonJournal(directory: directory).snapshot() == journal.snapshot())
    }

    @Test
    func `only an unrepairable append fences subsequent journal transactions`() throws {
        let harness = try ControllerHarness(), failing = Mutex(false)
        let directory = try StateDirectory(root: harness.root, observingWrites: { _ in
            if failing.withLock({ $0 }) {
                throw DaemonFailure.stateRollbackFailed(5)
            }
        })
        let journal = try DaemonJournal(directory: directory)
        let generation = try journal.allocate(intent: nil)
        failing.withLock { $0 = true }
        #expect(throws: DaemonFailure.stateRollbackFailed(5)) { try journal.mutate(generation: generation) { $0.pfPolicy = .error } }
        failing.withLock { $0 = false }
        #expect(throws: DaemonFailure.stateInvalidDocument) { try journal.mutate(generation: generation) { $0.pfPolicy = .lockdown } }
    }
}
