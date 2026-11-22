// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore

private struct SecretBytesTests {
    @Test
    func `empty comparison is equal and mismatches at every fixture byte are unequal`() throws {
        let empty = try SecretBytes(zeroedCount: 0)
        let sameEmpty = empty.constantTimeEquals(empty)
        #expect(sameEmpty)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var fixture = try Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/client1.key"))
        let original = try SecretBytes(wiping: &fixture)
        for index in 0 ..< original.count {
            var other = try SecretBytes(parsing: original)
            other.withUnsafeMutableBytes { $0[index] ^= 1 }
            let equal = original.constantTimeEquals(other)
            #expect(!equal)
        }
    }

    private final class Reports: Sendable {
        let items = Mutex<[SecretBytes.WipeReport]>([])
    }

    @Test
    func `deinit wipes the whole mapping`() throws {
        let reports = Reports()
        try SecretBytes.$wipeObserver.withValue({ report in reports.items.withLock { $0.append(report) } }) {
            var secret = try SecretBytes(zeroedCount: 32)
            secret.withUnsafeMutableBytes { raw in
                for index in raw.indices {
                    raw[index] = 0xA5
                }
            }
            _ = consume secret
        }
        let wiped = reports.items.withLock { $0 }
        #expect(wiped.count == 1)
        #expect(wiped.first?.byteCount == 32)
        #expect(wiped.first?.isZeroed == true)
        #expect((wiped.first?.mappedByteCount ?? 0) >= 32)
    }

    @Test
    func `copies are explicit and equal`() throws {
        let original = try Self.patterned(count: 48)
        let copy = try SecretBytes(parsing: original)
        let equal = copy.constantTimeEquals(original)
        #expect(equal)
        let slice = try SecretBytes(copying: original, range: 8 ..< 16)
        #expect(slice.count == 8)
        slice.withUnsafeBytes { #expect(Array($0) == (8 ..< 16).map { UInt8($0) }) }
    }

    @Test
    func `encode into requires matching length`() throws {
        let source = try Self.patterned(count: 16)
        var same = try SecretBytes(zeroedCount: 16)
        try source.encode(into: &same)
        let equal = same.constantTimeEquals(source)
        #expect(equal)
        var shorter = try SecretBytes(zeroedCount: 8)
        #expect(throws: SecretBytesError.outOfBounds) { try source.encode(into: &shorter) }
    }

    @Test
    func `copy at an offset is bounds checked`() throws {
        let source = try Self.patterned(count: 4)
        var target = try SecretBytes(zeroedCount: 8)
        try source.copyBytes(into: &target, at: 4)
        target.withUnsafeBytes { #expect(Array($0) == [0, 0, 0, 0, 0, 1, 2, 3]) }
        #expect(throws: SecretBytesError.outOfBounds) { try source.copyBytes(into: &target, at: 5) }
    }

    @Test
    func `wiping init zeroes the source data`() throws {
        var data = Data((0 ..< 32).map { UInt8($0) })
        let secret = try SecretBytes(wiping: &data)
        #expect(data.allSatisfy { $0 == 0 })
        #expect(data.count == 32)
        secret.withUnsafeBytes { #expect($0[31] == 31) }
    }

    @Test
    func `lengths are bounded`() {
        #expect(throws: SecretBytesError.invalidLength(-1)) { _ = try SecretBytes(zeroedCount: -1) }
        #expect(throws: SecretBytesError.invalidLength(SecretBytes.maximumCount + 1)) {
            _ = try SecretBytes(zeroedCount: SecretBytes.maximumCount + 1)
        }
    }

    @Test
    func `different contents compare unequal`() throws {
        let first = try Self.patterned(count: 8)
        var second = try SecretBytes(parsing: first)
        second.withUnsafeMutableBytes { $0[7] ^= 1 }
        let sameLength = first.constantTimeEquals(second)
        #expect(!sameLength)
        let shorter = try SecretBytes(zeroedCount: 7)
        let differentLength = first.constantTimeEquals(shorter)
        #expect(!differentLength)
    }

    private static func patterned(count: Int) throws -> SecretBytes {
        var secret = try SecretBytes(zeroedCount: count)
        secret.withUnsafeMutableBytes { raw in
            for index in raw.indices {
                raw[index] = UInt8(truncatingIfNeeded: index)
            }
        }
        return secret
    }
}
