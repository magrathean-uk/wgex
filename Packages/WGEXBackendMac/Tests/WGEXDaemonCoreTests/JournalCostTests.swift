// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct JournalCostTests {
    @Test
    func `a failed append rolls back every chunk before the next writer`() throws {
        let harness = try ControllerHarness()
        try harness.directory.append("append-test", with: Data([1, 2, 3]), durable: true)
        #expect(throws: HostTestError.self) {
            try harness.directory.append("append-test", with: Data(repeating: 42, count: 12000), durable: true, beforeCommit: {
                throw HostTestError.injected
            })
        }
        #expect(try harness.directory.read("append-test") == Data([1, 2, 3]))
        try harness.directory.append("append-test", with: Data([4]), durable: true)
        #expect(try harness.directory.read("append-test") == Data([1, 2, 3, 4]))
    }

    @Test
    func `legacy snapshots migrate before appending and obsolete records cannot replay over a checkpoint`() throws {
        let harness = try ControllerHarness()
        var legacy = DaemonJournalDocument(); legacy.schemaVersion = 1; legacy.pfPolicy = .lockdown
        try harness.directory.replace("journal.json", with: JSONEncoder().encode(legacy))
        let journal = try DaemonJournal(directory: harness.directory)
        #expect(journal.snapshot().schemaVersion == 2)
        #expect(journal.snapshot().pfPolicy == .lockdown)
        let first = try journal.allocate(intent: nil)
        try journal.mutate(generation: first) { $0.pfPolicy = .error }
        let obsolete = try #require(try harness.directory.read("journal.log"))
        let second = try journal.allocate(intent: nil)
        try journal.mutate(generation: second) { $0.pfPolicy = .lockdown }
        let current = try #require(try harness.directory.read("journal.log"))
        try harness.directory.replace("journal.log", with: obsolete + current)
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == journal.snapshot())
    }

    @Test
    func `long lived generations compact the append log without losing their latest state`() throws {
        let harness = try ControllerHarness()
        let generation = try harness.journal.allocate(intent: nil)
        for value in 0 ..< 600 {
            try harness.journal.mutate(generation: generation) { $0.cleanShutdownAt = Date(timeIntervalSince1970: Double(value)) }
        }
        #expect(try harness.directory.read("journal.log")?.count ?? 0 <= 65536)
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == harness.journal.snapshot())
    }

    @Test
    func `step history appends small unsynchronised records without rewriting large resources`() throws {
        let harness = try ControllerHarness()
        let writes = Mutex<[StateDirectoryWrite]>([])
        let reference = Mutex<DaemonJournal?>(nil)
        let directory = try StateDirectory(root: harness.root, observingWrites: { write in
            // Snapshot reads must remain possible while the writer is in the I/O path.
            _ = reference.withLock { $0 }?.snapshot()
            writes.withLock { $0.append(write) }
        })
        let journal = try DaemonJournal(directory: directory)
        reference.withLock { $0 = journal }
        defer { reference.withLock { $0 = nil } }
        let generation = try journal.allocate(intent: nil)
        var resource = GenerationResources(generation: generation)
        resource.routes = (0 ..< 1000).map { .init(destination: "10.\($0 / 256).\($0 % 256).0", prefixLength: 24, interfaceName: "utun7") }
        try journal.mutate(generation: generation) { $0.resources = [resource] }
        let offset = writes.withLock { $0.count }
        for step in DaemonStep.allCases {
            try journal.mutate(generation: generation) { $0.entries.append(.init(generation: generation, step: step, action: .willApply)) }
        }
        let entries = writes.withLock { Array($0.dropFirst(offset)) }
        #expect(entries.count == DaemonStep.allCases.count)
        #expect(entries.allSatisfy { $0.name == "journal.log" && $0.bytes < 8192 && !$0.durable })
        let resourceOffset = writes.withLock { $0.count }
        for step in [DaemonStep.createEngine, .configureEngine, .engineUp, .configureInterface, .installRoutes, .installDNS] {
            try journal.mutate(generation: generation) { $0.resources[0].attemptedSteps.insert(step) }
        }
        let resourceSteps = writes.withLock { Array($0.dropFirst(resourceOffset)) }
        #expect(resourceSteps.count == 6)
        #expect(resourceSteps.allSatisfy { $0.name == "journal.log" && $0.bytes < 8192 && $0.durable })
        #expect(writes.withLock { $0.allSatisfy { $0.maximumWriteSize < 8192 } })
        #expect(try DaemonJournal(directory: directory).snapshot() == journal.snapshot())
        guard let root = ProcessInfo.processInfo.environment["CLEAN_DEV_BUILDS"] else { return }
        #if WGEX_LAB_BUILD
            let variant = "lab"
        #else
            let variant = "plain"
        #endif
        let evidence = [
            "stepRecords": entries.count, "maximumStepRecordBytes": entries.map(\.bytes).max() ?? 0,
            "maximumPhysicalWriteBytes": writes.withLock { $0.map(\.maximumWriteSize).max() ?? 0 },
            "resourceStepRecords": resourceSteps.count, "maximumResourceStepRecordBytes": resourceSteps.map(\.bytes).max() ?? 0,
        ]
        try JSONEncoder().encode(evidence)
            .write(to: URL(fileURLWithPath: root).appendingPathComponent("M1-05-journal-cost-\(variant).json"))
    }

    @Test
    func `resource policy and ownership records are durable while bookkeeping is not`() throws {
        let harness = try ControllerHarness(), writes = Mutex<[StateDirectoryWrite]>([])
        let directory = try StateDirectory(root: harness.root, observingWrites: { write in writes.withLock { $0.append(write) } })
        let journal = try DaemonJournal(directory: directory)
        let generation = try journal.allocate(intent: nil)
        writes.withLock { $0 = [] }
        try journal.mutate(generation: generation) { $0.loginSuspended = true }
        #expect(writes.withLock { $0.count == 1 && !$0[0].durable })
        writes.withLock { $0 = [] }
        // The clean-shutdown mark and cutover changes checkpoint the whole document (durable journal.json
        // replace plus a log truncate) so offline recovery reads the checkpoint without replaying the log.
        try journal.mutate(generation: generation) { $0.cleanShutdownAt = Date(timeIntervalSince1970: 100) }
        #expect(writes.withLock { $0.contains { $0.name == "journal.json" && $0.durable } && $0.allSatisfy(\.durable) })
        writes.withLock { $0 = [] }
        try journal.mutate(generation: generation) { $0.pfPolicy = .lockdown }
        try journal.mutate(generation: generation) { $0.resources = [GenerationResources(generation: generation)] }
        try journal.mutate(generation: generation) { $0.pfEnableAttempted = .init(bootSession: UUID(), pid: 123, at: .distantPast) }
        #expect(writes.withLock { $0.count == 3 && $0.allSatisfy(\.durable) })
        #expect(try DaemonJournal(directory: directory).snapshot() == journal.snapshot())
    }

    @Test
    func `a torn final append is discarded and committed corruption fails closed`() throws {
        let harness = try ControllerHarness()
        let generation = try harness.journal.allocate(intent: nil)
        try harness.journal.mutate(generation: generation) { $0.pfPolicy = .lockdown }
        let baseline = harness.journal.snapshot()
        let committed = try #require(try harness.directory.read("journal.log"))
        try harness.journal.mutate(generation: generation) {
            $0.entries.append(.init(generation: generation, step: .commit, action: .didApply))
        }
        let complete = try #require(try harness.directory.read("journal.log"))
        try harness.directory.replace("journal.log", with: Data(complete.dropLast(3)))
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == baseline)
        #expect(try harness.directory.read("journal.log") == committed)
        var corrupt = committed; corrupt[corrupt.count / 2] ^= 1
        try harness.directory.replace("journal.log", with: corrupt)
        #expect(throws: DaemonFailure.stateInvalidDocument) { _ = try DaemonJournal(directory: harness.directory) }
    }

    @Test
    func `failed publication keeps memory and the durable document unchanged`() throws {
        let harness = try ControllerHarness(), fail = Mutex(false)
        let directory = try StateDirectory(root: harness.root, observingWrites: { _ in
            if fail.withLock({ $0 }) {
                throw HostTestError.injected
            }
        })
        let journal = try DaemonJournal(directory: directory)
        let generation = try journal.allocate(intent: nil)
        let baseline = journal.snapshot()
        fail.withLock { $0 = true }
        #expect(throws: HostTestError.self) { try journal.mutate(generation: generation) { $0.pfPolicy = .lockdown } }
        #expect(journal.snapshot() == baseline)
        #expect(try DaemonJournal(directory: harness.directory).snapshot() == baseline)
    }
}
