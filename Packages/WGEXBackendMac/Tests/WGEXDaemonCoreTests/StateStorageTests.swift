// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXProfileStore

@Suite(.timeLimit(.minutes(1)))
private struct StateStorageTests {
    @Test
    func `state directory refuses symlinks unsafe modes wrong owners and traversal`() throws {
        let harness = try ControllerHarness()
        let root = harness.root
        let file = root.appendingPathComponent("item")
        try harness.directory.replace("item", with: Data([1]))
        #expect(chmod(file.path, 0o644) == 0)
        #expect(throws: DaemonFailure.stateUnsafeMetadata) { _ = try harness.directory.read("item") }
        #expect(chmod(file.path, 0o600) == 0)
        #expect(throws: DaemonFailure.stateUnsafeMetadata) { _ = try StateDirectory(root: root, ownerUID: geteuid() + 1) }
        #expect(throws: DaemonFailure.stateUnsafePath) { _ = try harness.directory.read("../item") }
        #expect(throws: DaemonFailure.stateUnsafePath) { _ = try harness.directory.directory("a/b") }
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        #expect(throws: DaemonFailure.stateUnsafePath) { _ = try harness.directory.read("link") }
        #expect(throws: DaemonFailure.stateUnsafePath) { try harness.directory.replace("link", with: Data([2])) }
        #expect(throws: DaemonFailure.stateUnsafePath) { try harness.directory.append("link", with: Data([2]), durable: true) }
        #expect(throws: DaemonFailure.stateUnsafePath) { try harness.directory.truncate("link", to: 0, durable: true) }
        let dirLink = root.appendingPathComponent("dirlink")
        try FileManager.default.createSymbolicLink(at: dirLink, withDestinationURL: root)
        #expect(throws: DaemonFailure.stateUnsafePath) { _ = try StateDirectory(root: dirLink) }
        #expect(throws: DaemonFailure.stateUnsafePath) { _ = try harness.directory.directory("dirlink") }
        try FileManager.default.linkItem(at: file, to: root.appendingPathComponent("hardlink"))
        #expect(throws: DaemonFailure.stateUnsafeMetadata) { _ = try harness.directory.read("item") }
        #expect(throws: DaemonFailure.stateUnsafeMetadata) { try harness.directory.append("item", with: Data([2]), durable: true) }
        #expect(throws: DaemonFailure.stateUnsafeMetadata) { try harness.directory.truncate("item", to: 0, durable: true) }
    }

    @Test
    func `interruption before rename preserves old file and removes temporary file`() throws {
        let harness = try ControllerHarness()
        try harness.directory.replace("state", with: Data([1, 2]))
        #expect(throws: HostTestError.self) {
            try harness.directory.replace("state", with: Data([3, 4]), beforeRename: { throw HostTestError.injected })
        }
        #expect(try harness.directory.read("state") == Data([1, 2]))
        #expect(try !harness.directory.filenames().contains { $0.hasPrefix(".write-") })
        try harness.directory.replace("state", with: Data([5]))
        #expect(try harness.directory.read("state") == Data([5]))
    }

    @Test
    func `descriptor remains rooted when the pathname is replaced`() throws {
        let harness = try ControllerHarness()
        let child = try harness.directory.directory("child")
        try child.replace("state", with: Data([1]))
        try FileManager.default.moveItem(at: harness.root.appendingPathComponent("child"), to: harness.root.appendingPathComponent("moved"))
        try FileManager.default.createSymbolicLink(at: harness.root.appendingPathComponent("child"), withDestinationURL: harness.root)
        try child.replace("state", with: Data([2]))
        #expect(try child.read("state") == Data([2]))
        #expect(try harness.directory.read("state") == nil)
    }

    @Test
    func `wrapped secrets round trip replace atomically and reject tampering and wrong keys`() async throws {
        let harness = try ControllerHarness()
        let id = SecretID(profileID: harness.profile.id, kind: .privateKey)
        let original = try ControllerHarness.testKey()
        try await harness.store.store(SecretBytes(parsing: original), for: id)
        let loaded = try await harness.store.load(id)
        let equal = loaded.constantTimeEquals(original); #expect(equal)
        await #expect(throws: SecretStoreError.duplicate) { try await harness.store.store(ControllerHarness.testKey(), for: id) }
        let wrong = try DaemonSecretStore(
            directory: harness.directory,
            keyProvider: InMemoryDaemonKeyProvider(key: SecretBytes(zeroedCount: 32)),
        )
        await #expect(throws: SecretStoreError.unavailable) { _ = try await wrong.load(id) }
        try await harness.store.replace(id, with: SecretBytes(zeroedCount: 32))
        let replaced = try await harness.store.load(id)
        let changed = !replaced.constantTimeEquals(original); #expect(changed)
        let secrets = try harness.directory.directory("secrets")
        let name = try #require(try secrets.filenames().first { $0.hasSuffix(".blob") })
        var encrypted = try #require(try secrets.read(name))
        encrypted[encrypted.count - 1] ^= 1
        try secrets.replace(name, with: encrypted)
        await #expect(throws: SecretStoreError.unavailable) { _ = try await harness.store.load(id) }
        try await harness.store.delete(id)
        #expect(try await !harness.store.exists(id))
    }

    @Test
    func `minimum build floor rejects rollback survives restart and permits explicit lowering`() throws {
        let harness = try ControllerHarness()
        let floor = MinimumBuildFloor(directory: harness.directory)
        try floor.admit(build: 20); try floor.admit(build: 20)
        #expect(throws: DaemonFailure.floorDowngradeDetected) { try floor.admit(build: 19) }
        #expect(try MinimumBuildFloor(directory: harness.directory).read() == 20)
        try floor.allowDowngrade(to: 10); try floor.admit(build: 11)
        #expect(try floor.read() == 11)
        try harness.directory.replace("min-build", with: Data("broken".utf8))
        #expect(throws: DaemonFailure.stateInvalidDocument) { try floor.admit(build: 99) }
    }

    @Test
    func `journal survives restart and fences stale writes without publishing them`() throws {
        let harness = try ControllerHarness()
        #expect(GenerationResources.protocol2RouteFlag == RTF_PROTO2)
        let first = try harness.journal.allocate(intent: nil)
        let second = try harness.journal.allocate(intent: nil)
        #expect(throws: DaemonFailure.journalStaleGeneration) {
            try harness.journal.mutate(generation: first) { $0.pfPolicy = .connected(interfaceName: "foreign", endpoints: []) }
        }
        let restarted = try DaemonJournal(directory: harness.directory)
        #expect(restarted.snapshot().generation == second)
        #expect(restarted.snapshot().pfPolicy == .disconnected)
        try restarted.mutate(generation: second) { $0.generation = Generation(rawValue: UInt64.max) }
        #expect(throws: DaemonFailure.journalExhausted) { _ = try restarted.allocate(intent: nil) }
    }
}
