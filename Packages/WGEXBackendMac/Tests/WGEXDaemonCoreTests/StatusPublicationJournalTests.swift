// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore

/// DEC-011: the status sequence belongs to one daemon run.
private struct StatusPublicationJournalTests {
    @Test
    func `sequence is 1 on the first publication of each run and rises by one after it`() throws {
        let first = StatusPublicationJournal()
        #expect(try [first.next(), first.next(), first.next()] == [1, 2, 3])
        let restarted = StatusPublicationJournal()
        #expect(try restarted.next() == 1)
    }

    @Test
    func `a stale persisted sequence file from an older daemon does not move the first publication`() throws {
        let harness = try ControllerHarness()
        try harness.directory.replace("status-sequence.json", with: JSONEncoder().encode(UInt64(9_000_000)))
        #expect(try StatusPublicationJournal(directory: harness.directory).next() == 1)
    }
}
