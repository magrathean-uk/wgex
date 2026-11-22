// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore

private struct SecretLifetimeTests {
    private enum Injected: Error { case failure }
    private final class Tracker: Sendable {
        let allocated = Mutex(0)
        let reports = Mutex<[SecretBytes.WipeReport]>([])

        var allocator: SecretBytes.Allocator {
            SecretBytes.Allocator(allocate: { count in
                self.allocated.withLock { $0 += 1 }
                return SecretBytes.Allocator.system.allocate(count)
            }, lock: { _, _ in false }, didWipe: { report in self.reports.withLock { $0.append(report) } })
        }
    }

    @Test
    func `allocator proves zeroing on success moves throws and rejected initialisers`() throws {
        let tracker = Tracker()
        try SecretBytes.$allocator.withValue(tracker.allocator) {
            try Self.destroy(Self.patterned(0))
            try Self.destroy(Self.patterned(4097))
            let source = try Self.patterned(32)
            let privateKey = try PrivateKey(parsing: source)
            let presharedKey = try PresharedKey(parsing: source)
            _ = consume privateKey; _ = consume presharedKey
            #expect(throws: KeyError.invalidLength(31)) { _ = try PrivateKey(bytes: Self.patterned(31)) }
            #expect(throws: KeyError.invalidLength(33)) { _ = try PresharedKey(bytes: Self.patterned(33)) }
            #expect(throws: Injected.failure) { try Self.throwingScope() }
            #expect(throws: KeyError.invalidEncoding) {
                let invalid = try Self.patterned(44)
                _ = try PrivateKey(parsing: invalid, encoding: .base64)
            }
        }
        let reports = tracker.reports.withLock { $0 }
        #expect(tracker.allocated.withLock { $0 } == reports.count)
        #expect(reports.count == 10)
        let allZeroed = reports.allSatisfy(\.isZeroed)
        #expect(allZeroed)
        #expect(reports.allSatisfy { $0.mappedByteCount >= $0.byteCount })
    }

    @Test
    func `wipe hook survives moving outside allocation context`() throws {
        let tracker = Tracker()
        var slot: SecretBytes?
        try SecretBytes.$allocator.withValue(tracker.allocator) { slot = try Self.patterned(32) }
        if let moved = consume slot { Self.destroy(consume moved) } else {
            Issue.record("Missing moved buffer")
        }
        #expect(tracker.reports.withLock { $0.count } == 1)
        #expect(tracker.reports.withLock { $0.allSatisfy(\.isZeroed) })
    }

    @Test
    func `cancellation and thrown byte access still wipe`() async throws {
        let tracker = Tracker()
        let task = Task {
            try SecretBytes.$allocator.withValue(tracker.allocator) {
                let bytes = try Self.patterned(32)
                do { try bytes.withUnsafeBytes { _ throws in throw Injected.failure } } catch {}
                withUnsafeCurrentTask { $0?.cancel() }
                try Task.checkCancellation()
            }
        }
        do { try await task.value; Issue.record("Expected cancellation") } catch is CancellationError {} catch { throw error }
        #expect(tracker.reports.withLock { $0.count } == 1)
        #expect(tracker.reports.withLock { $0.allSatisfy(\.isZeroed) })
    }

    @Test
    func `allocation failure wipes Data and produces a typed error`() {
        let allocator = SecretBytes.Allocator(allocate: { _ in errno = ENOMEM; return nil }, lock: { _, _ in false }, didWipe: nil)
        var data = Data(repeating: 0xA5, count: 32)
        SecretBytes.$allocator.withValue(allocator) {
            #expect(throws: SecretBytesError.allocationFailed(ENOMEM)) { _ = try SecretBytes(wiping: &data) }
            #expect(throws: KeyError.buffer(.allocationFailed(ENOMEM))) { _ = try PrivateKey.generate() }
        }
        #expect(data.allSatisfy { $0 == 0 })
    }

    private static func patterned(_ count: Int) throws -> SecretBytes {
        var secret = try SecretBytes(zeroedCount: count)
        secret.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0xA5) }
        let locked = secret.isLocked
        #expect(!locked)
        return secret
    }

    private static func destroy(_ bytes: consuming SecretBytes) {
        _ = consume bytes
    }

    private static func throwingScope() throws {
        let bytes = try patterned(32)
        _ = bytes.count
        throw Injected.failure
    }
}
