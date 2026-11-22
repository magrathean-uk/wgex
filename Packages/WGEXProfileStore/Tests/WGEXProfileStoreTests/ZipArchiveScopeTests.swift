// SPDX-License-Identifier: MIT
import Compression
import Foundation
import Testing
import WGEXCore
@testable import WGEXProfileStore

private struct ZipArchiveScopeTests {
    @Test
    func `ignored entries have no parser cap or UTF8 name requirement`() throws {
        let ignored = Entry(name: [255] + Array(".bin".utf8), bytes: [UInt8](repeating: 65, count: 300_000))
        let archive = try Self.archive([ignored, Entry(name: Array("a.conf".utf8), bytes: [65])])
        let entries = try ZipArchiveReader.archive(archive)
        #expect(entries.count == 1)
        #expect(entries.first?.0 == "a")
        #expect(entries.first?.1 == [65])
        #expect(throws: ZipArchiveReader.Failure.invalid) {
            try ZipArchiveReader.archive(Self.archive([Entry(name: [255] + Array(".conf".utf8), bytes: [65])]))
        }
    }

    @Test
    func `ignored expanded bytes count towards the total bound`() throws {
        let half = ZipArchiveReader.maximumBytes / 2
        let first = Entry(name: Array("one.bin".utf8), bytes: [], advertisedSize: half)
        let second = Entry(name: Array("two.bin".utf8), bytes: [], advertisedSize: half)
        let config = Entry(name: Array("a.conf".utf8), bytes: [65])
        #expect(try ZipArchiveReader.archive(Self.archive([first, config])).count == 1)
        #expect(throws: ZipArchiveReader.Failure.tooLarge) {
            try ZipArchiveReader.archive(Self.archive([first, second, config]))
        }
    }

    @Test
    func `ignored entries still count towards the entry limit`() throws {
        let limit = ZipArchiveReader.maximumEntries
        let ignored = (0 ..< limit - 1).map { Entry(name: Array("\($0).bin".utf8), bytes: []) }
        let config = Entry(name: Array("a.conf".utf8), bytes: [65])
        #expect(try ZipArchiveReader.archive(Self.archive(ignored + [config])).count == 1)
        #expect(throws: ZipArchiveReader.Failure.tooLarge) {
            try ZipArchiveReader.archive(Self.archive(ignored + [config, Entry(name: Array("extra.bin".utf8), bytes: [])]))
        }
    }

    /// Scans with a visitor that wipes in place (`wipe`), keeps the payload (`retain`) or wipes a private copy instead.
    private static func measure(_ archive: Data, behaviour: Behaviour) throws -> (visited: Int, accounting: ZipArchiveReader.Accounting) {
        let accounting = ZipArchiveReader.Accounting()
        var kept: [[UInt8]] = []
        var visited = 0
        try ZipArchiveReader.scan(archive, accounting: accounting) { _, bytes in
            #expect(bytes.count == ZipArchiveReader.maximumEntryBytes)
            switch behaviour {
            case .wipe:
                let address = bytes.withUnsafeBufferPointer { $0.baseAddress }
                bytes.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) }
                #expect(address == bytes.withUnsafeBufferPointer { $0.baseAddress }, "in-place wipe reallocated")
            case .retain: kept.append(bytes)
            case .copyThenWipe:
                var copy = bytes
                copy.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) }
            }
            visited += 1
        }
        return (visited, accounting)
    }

    private enum Behaviour { case wipe, retain, copyThenWipe }

    @Test
    func `scan holds exactly one entry at the count and size limits`() throws {
        let size = ZipArchiveReader.maximumEntryBytes
        let body = [UInt8](repeating: 65, count: size)
        let entries = (0 ..< ZipArchiveReader.maximumEntries).map { Entry(name: Array("T\($0).conf".utf8), bytes: body, compressed: true) }
        let archive = try Self.archive(entries)
        let limit = ZipArchiveReader.maximumEntries

        let bounded = try Self.measure(archive, behaviour: .wipe)
        #expect(bounded.visited == limit)
        #expect(bounded.accounting.peak == size)
        #expect(bounded.accounting.live == 0)
        #expect(bounded.accounting.retained == 0)
        #expect(bounded.accounting.unwiped == 0)

        // Controls: each defect the accounting must catch.
        let kept = try Self.measure(archive, behaviour: .retain)
        #expect(kept.visited == limit)
        #expect(kept.accounting.retained == limit * size)
        #expect(kept.accounting.peak == limit * size)
        let copied = try Self.measure(archive, behaviour: .copyThenWipe)
        #expect(copied.accounting.unwiped == limit * size)

        #expect(try ZipArchiveReader.archive(archive).count == limit)
        // A sliced Data (non-zero start index) reads the same.
        let padded = Data([1, 2, 3]) + archive
        var count = 0
        try ZipArchiveReader.scan(padded.dropFirst(3)) { _, _ in count += 1 }
        #expect(count == limit)
    }

    @Test
    func `a full archive of configurations reads back in order`() throws {
        let entries = (0 ..< ZipArchiveReader.maximumEntries).map { Entry(name: Array("T\($0).conf".utf8), bytes: [UInt8($0 % 251)]) }
        let read = try ZipArchiveReader.archive(Self.archive(entries))
        #expect(read.count == ZipArchiveReader.maximumEntries)
        #expect(read.first?.0 == "T0")
        #expect(read.last?.0 == "T1023")
    }

    @Test
    func `configuration parser cap remains strict`() throws {
        let bytes = [UInt8](repeating: 65, count: ParseLimits.default.maximumBytes)
        #expect(try ZipArchiveReader.archive(Self.archive([Entry(name: Array("a.CONF".utf8), bytes: bytes, compressed: true)])).count == 1)
        #expect(throws: ZipArchiveReader.Failure.tooLarge) {
            try ZipArchiveReader.archive(Self.archive([Entry(name: Array("a.conf".utf8), bytes: bytes + [65], compressed: true)]))
        }
    }

    @Test
    func `encrypted and ZIP64 archives report unsupported`() throws {
        let entries = [Entry(name: Array("a.conf".utf8), bytes: [65])]
        #expect(throws: ZipArchiveReader.Failure.unsupported) { try ZipArchiveReader.archive(Self.archive(entries, flags: 1)) }
        var zip64 = try Self.archive(entries)
        zip64.replaceSubrange(zip64.count - 6 ..< zip64.count - 2, with: [255, 255, 255, 255])
        #expect(throws: ZipArchiveReader.Failure.unsupported) { try ZipArchiveReader.archive(zip64) }
    }

    private struct Entry {
        let name: [UInt8]
        let bytes: [UInt8]
        var compressed = false
        /// Forged uncompressed size for an entry the reader skips; nil advertises the real size.
        var advertisedSize: Int?
    }

    private enum FixtureError: Error { case compression }

    private static func compressed(_ bytes: [UInt8]) throws -> [UInt8] {
        var result = [UInt8](repeating: 0, count: bytes.count + 1024)
        let count = result.withUnsafeMutableBufferPointer { output in
            bytes.withUnsafeBufferPointer { input in
                guard let target = output.baseAddress, let source = input.baseAddress else { return 0 }
                var stream = compression_stream(dst_ptr: target, dst_size: output.count, src_ptr: source, src_size: input.count, state: nil)
                guard compression_stream_init(&stream, COMPRESSION_STREAM_ENCODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK
                else { return 0 }
                defer { compression_stream_destroy(&stream) }
                stream.dst_ptr = target; stream.dst_size = output.count
                stream.src_ptr = source; stream.src_size = input.count
                guard compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue)) == COMPRESSION_STATUS_END,
                      stream.src_size == 0 else { return 0 }
                return output.count - stream.dst_size
            }
        }
        guard count > 0 else { throw FixtureError.compression }
        return Array(result.prefix(count))
    }

    private static func archive(_ entries: [Entry], flags: UInt16 = 0) throws -> Data {
        var result = Data(), central = Data()
        func u16(_ value: UInt16, to data: inout Data) {
            data.append(UInt8(truncatingIfNeeded: value)); data.append(UInt8(truncatingIfNeeded: value >> 8))
        }
        func u32(_ value: UInt32, to data: inout Data) {
            u16(UInt16(truncatingIfNeeded: value), to: &data); u16(UInt16(truncatingIfNeeded: value >> 16), to: &data)
        }
        // Entries that share one body (array equality short-circuits on shared storage) are packed and summed once.
        var memo: (bytes: [UInt8], payload: [UInt8], crc: UInt32)?
        for entry in entries {
            let payload: [UInt8], crc: UInt32
            if let memo, memo.bytes == entry.bytes, entry.compressed {
                payload = memo.payload; crc = memo.crc
            } else {
                payload = try entry.compressed ? compressed(entry.bytes) : entry.bytes
                crc = CRC32.checksum(entry.bytes)
                if entry.compressed {
                    memo = (entry.bytes, payload, crc)
                }
            }
            let method: UInt16 = entry.compressed ? 8 : 0
            let local = result.count
            u32(0x0403_4B50, to: &result); u16(20, to: &result); u16(flags, to: &result); u16(method, to: &result)
            u32(0, to: &result); u32(crc, to: &result); u32(UInt32(payload.count), to: &result)
            u32(UInt32(entry.advertisedSize ?? entry.bytes.count), to: &result); u16(UInt16(entry.name.count), to: &result); u16(
                0,
                to: &result,
            )
            result.append(contentsOf: entry.name); result.append(contentsOf: payload)
            u32(0x0201_4B50, to: &central); u16(20, to: &central); u16(20, to: &central)
            u16(flags, to: &central); u16(method, to: &central); u32(0, to: &central); u32(crc, to: &central)
            u32(UInt32(payload.count), to: &central); u32(UInt32(entry.advertisedSize ?? entry.bytes.count), to: &central)
            u16(UInt16(entry.name.count), to: &central); u16(0, to: &central); u16(0, to: &central)
            u16(0, to: &central); u16(0, to: &central); u32(0, to: &central); u32(UInt32(local), to: &central)
            central.append(contentsOf: entry.name)
        }
        let offset = result.count; result.append(central)
        u32(0x0605_4B50, to: &result); u16(0, to: &result); u16(0, to: &result)
        u16(UInt16(entries.count), to: &result); u16(UInt16(entries.count), to: &result)
        u32(UInt32(central.count), to: &result); u32(UInt32(offset), to: &result); u16(0, to: &result)
        return result
    }
}
