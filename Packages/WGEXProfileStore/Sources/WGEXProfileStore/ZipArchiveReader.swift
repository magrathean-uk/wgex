// SPDX-License-Identifier: MIT
import Compression
import Foundation
import WGEXCore

/// Bounded ZIP32 import. Names are display labels only; no entry ever touches disk.
public enum ZipArchiveReader {
    /// At most 1,024 central-directory entries, including ignored files and directories (DEC-010: the Mac app's Export All
    /// writes the same number).
    public static let maximumEntries = 1024
    /// Each configuration entry is capped at the parser's byte limit.
    public static let maximumEntryBytes = ParseLimits.default.maximumBytes
    /// Compressed input and the total uncompressed archive are each capped at the entry bound times the per-entry bound.
    public static let maximumBytes = maximumEntries * maximumEntryBytes
    /// Failures never contain entry names or configuration content.
    public enum Failure: Error, Sendable { case invalid, unsupported, tooLarge }

    /// Reads `.conf` entries with CRC verification and the parser's per-entry byte cap.
    /// Only configuration names must be valid UTF-8. Other entries are skipped without
    /// decoding their payloads, but their advertised expanded bytes and entry count still count towards the archive caps.
    /// Stored and raw-deflate data are supported; encryption, ZIP64 and multi-disk ZIPs are rejected.
    public static func archive(_ data: Data) throws -> [(String, [UInt8])] {
        var result: [(String, [UInt8])] = []
        try scan(data) { name, bytes in result.append((name, bytes)) }
        return result
    }

    /// Visits configuration entries one at a time, in archive order. The reader holds no copy of the archive and at most
    /// one decoded entry (at most `maximumEntryBytes`) at once, so a visitor that parses and releases each payload keeps
    /// the whole import within the archive's own mapping plus one entry. A later entry can still fail after earlier
    /// ones were visited, so a caller that must accept an archive whole stages its results until `scan` returns.
    /// The payload is passed `inout` and uniquely owned: a visitor parses and wipes it in place (`parseWgQuick(&bytes)`)
    /// instead of copying it, so no second payload-sized allocation exists. `accounting` measures this when supplied.
    public static func scan(
        _ data: Data, accounting: Accounting? = nil, visit: (String, inout [UInt8]) throws -> Void,
    ) throws {
        guard data.count <= maximumBytes else { throw Failure.tooLarge }
        guard data.count >= 22 else { throw Failure.invalid }
        let reader = Reader(bytes: data.startIndex == 0 ? data : Data(data))
        let (central, end, count) = try reader.directory()
        var cursor = central; var total = 0; var found = 0
        var spans: [Range<Int>] = []
        for _ in 0 ..< count {
            let entry = try reader.entry(at: cursor, centralEnd: end, payloadEnd: central)
            guard entry.size <= maximumBytes - total else { throw Failure.tooLarge }
            total += entry.size
            guard !spans.contains(where: { $0.overlaps(entry.span) }) else { throw Failure.invalid }
            spans.append(entry.span)
            if let name = entry.name {
                var bytes = try decode(reader.bytes[entry.payload], size: entry.size, method: entry.method)
                guard checksum(bytes) == entry.crc else { throw Failure.invalid }
                let leaf = name.split(separator: "/", omittingEmptySubsequences: false).last ?? ""
                accounting?.acquire(bytes.count)
                try visit(String(leaf.dropLast(5)), &bytes)
                accounting?.release(&bytes)
                found += 1
            }
            cursor = entry.next
        }
        guard cursor == end, found > 0 else { throw Failure.invalid }
    }

    /// Deterministic measurement of what a `scan` holds, for tests. `live` is the decoded payload bytes the reader still
    /// accounts for, `peak` its high-water mark. After each visit the payload counts as released only when the visitor
    /// left the buffer uniquely owned (`retained` counts bytes it kept alive) and zeroed it (`unwiped` counts bytes
    /// left readable, which is what a visitor that parsed a private copy instead of the payload leaves behind).
    public final class Accounting: @unchecked Sendable {
        public private(set) var live = 0, peak = 0, retained = 0, unwiped = 0
        public init() {}

        fileprivate func acquire(_ count: Int) {
            live += count; peak = max(peak, live)
        }

        fileprivate func release(_ bytes: inout [UInt8]) {
            let count = bytes.count
            if bytes.contains(where: { $0 != 0 }) {
                unwiped += count
            }
            let before = bytes.withUnsafeBufferPointer { $0.baseAddress }
            bytes.withUnsafeMutableBufferPointer { _ in }
            let after = bytes.withUnsafeBufferPointer { $0.baseAddress }
            if before != after {
                retained += count
            } else {
                live -= count
            }
        }
    }

    private static let crcTable: [UInt32] = (0 ..< 256).map { index in
        (0 ..< 8).reduce(UInt32(index)) { value, _ in (value >> 1) ^ (value & 1 == 0 ? 0 : 0xEDB8_8320) }
    }

    /// Same checksum as `CRC32.checksum`, over a contiguous buffer so a 256 MiB archive does not pay per-byte iterator cost.
    private static func checksum(_ bytes: [UInt8]) -> UInt32 {
        crcTable.withUnsafeBufferPointer { table in
            bytes.withUnsafeBufferPointer { buffer in
                var crc = UInt32.max
                for byte in buffer {
                    crc = (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 255)]
                }
                return ~crc
            }
        }
    }

    private struct Entry {
        let name: String?
        let size: Int
        let crc: UInt32
        let method: UInt16
        let payload: Range<Int>
        let span: Range<Int>
        let next: Int
    }

    private struct Reader {
        let bytes: Data

        func directory() throws -> (start: Int, end: Int, count: Int) {
            guard let end = try stride(from: bytes.count - 22, through: max(0, bytes.count - 65557), by: -1)
                .first(where: { try u32($0) == 0x0605_4B50 && $0 + 22 + Int(u16($0 + 20)) == bytes.count })
            else { throw Failure.invalid }
            guard try u16(end + 4) == 0, try u16(end + 6) == 0 else { throw Failure.unsupported }
            let count = try Int(u16(end + 10))
            guard count != 0xFFFF else { throw Failure.unsupported }
            guard count > 0, count <= maximumEntries else { throw Failure.tooLarge }
            guard try Int(u16(end + 8)) == count else { throw Failure.unsupported }
            let central = try Int(u32(end + 16)), centralSize = try Int(u32(end + 12))
            guard central != Int(UInt32.max), centralSize != Int(UInt32.max) else { throw Failure.unsupported }
            guard central <= end, centralSize == end - central else { throw Failure.invalid }
            return (central, end, count)
        }

        func range(_ offset: Int, _ length: Int, end: Int? = nil) throws -> Range<Int> {
            let limit = end ?? bytes.count
            guard offset >= 0, length >= 0, limit <= bytes.count, offset <= limit, length <= limit - offset
            else { throw Failure.invalid }
            return offset ..< offset + length
        }

        func u16(_ offset: Int) throws -> UInt16 {
            let span = try range(offset, 2)
            return UInt16(bytes[span.lowerBound]) | UInt16(bytes[span.lowerBound + 1]) << 8
        }

        func u32(_ offset: Int) throws -> UInt32 {
            try UInt32(u16(offset)) | UInt32(u16(offset + 2)) << 16
        }

        func extra(_ offset: Int, length: Int) throws {
            let end = try range(offset, length).upperBound
            var cursor = offset
            while cursor < end {
                _ = try range(cursor, 4, end: end)
                guard try u16(cursor) != 1 else { throw Failure.unsupported }
                cursor = try range(cursor + 4, Int(u16(cursor + 2)), end: end).upperBound
            }
        }

        func validateMethod(at cursor: Int, flags: UInt16, method: UInt16) throws {
            guard flags & ~UInt16(0x080E) == 0, method == 0 || method == 8,
                  try u16(cursor + 6) < 45, try u16(cursor + 34) == 0 else { throw Failure.unsupported }
        }

        func entry(at cursor: Int, centralEnd: Int, payloadEnd: Int) throws -> Entry {
            _ = try range(cursor, 46, end: centralEnd)
            guard try u32(cursor) == 0x0201_4B50 else { throw Failure.invalid }
            let flags = try u16(cursor + 8), method = try u16(cursor + 10)
            try validateMethod(at: cursor, flags: flags, method: method)
            let packed = try Int(u32(cursor + 20)), size = try Int(u32(cursor + 24))
            let local = try Int(u32(cursor + 42))
            guard packed != Int(UInt32.max), size != Int(UInt32.max), local != Int(UInt32.max) else { throw Failure.unsupported }
            let nameLength = try Int(u16(cursor + 28)), extraLength = try Int(u16(cursor + 30))
            let next = try range(cursor + 46, nameLength + extraLength + Int(u16(cursor + 32)), end: centralEnd).upperBound
            let nameBytes = try bytes[range(cursor + 46, nameLength, end: centralEnd)]
            let name = try configurationName(nameBytes, size: size)
            try extra(cursor + 46 + nameLength, length: extraLength)
            _ = try range(local, 30, end: payloadEnd)
            guard try u32(local) == 0x0403_4B50, try u16(local + 6) == flags, try u16(local + 8) == method else { throw Failure.invalid }
            guard try u16(local + 4) < 45 else { throw Failure.unsupported }
            let localNameLength = try Int(u16(local + 26)), localExtraLength = try Int(u16(local + 28))
            let localName = try range(local + 30, localNameLength, end: payloadEnd)
            guard bytes[localName].elementsEqual(nameBytes) else { throw Failure.invalid }
            try extra(localName.upperBound, length: localExtraLength)
            let payload = try range(localName.upperBound + localExtraLength, packed, end: payloadEnd)
            let crc = try u32(cursor + 16)
            var spanEnd = payload.upperBound
            if flags & 8 == 0 {
                guard try u32(local + 14) == crc, try Int(u32(local + 18)) == packed, try Int(u32(local + 22)) == size
                else { throw Failure.invalid }
            } else {
                let descriptor = try u32(spanEnd) == 0x0807_4B50 ? spanEnd + 4 : spanEnd
                spanEnd = try range(descriptor, 12, end: payloadEnd).upperBound
                guard try u32(descriptor) == crc, try Int(u32(descriptor + 4)) == packed, try Int(u32(descriptor + 8)) == size
                else { throw Failure.invalid }
            }
            return Entry(name: name, size: size, crc: crc, method: method, payload: payload, span: local ..< spanEnd, next: next)
        }

        private func configurationName(_ bytes: Data, size: Int) throws -> String? {
            let suffix = bytes.suffix(5).map { (65 ... 90).contains($0) ? $0 + 32 : $0 }
            guard suffix.elementsEqual(".conf".utf8) else { return nil }
            guard let name = String(bytes: bytes, encoding: .utf8) else { throw Failure.invalid }
            guard size <= maximumEntryBytes else { throw Failure.tooLarge }
            return name
        }
    }

    private static func decode(_ payload: Data, size: Int, method: UInt16) throws -> [UInt8] {
        if method == 0 {
            guard payload.count == size else { throw Failure.invalid }
            return Array(payload)
        }
        // One extra byte detects a forged advertised size instead of accepting a truncated stream.
        var bytes = [UInt8](repeating: 0, count: size + 1)
        let valid = bytes.withUnsafeMutableBufferPointer { target in
            payload.withUnsafeBytes { (source: UnsafeRawBufferPointer) in
                guard let output = target.baseAddress, let raw = source.baseAddress else { return false }
                let input = raw.assumingMemoryBound(to: UInt8.self)
                var stream = compression_stream(dst_ptr: output, dst_size: target.count, src_ptr: input, src_size: source.count, state: nil)
                guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK
                else { return false }
                defer { compression_stream_destroy(&stream) }
                stream.dst_ptr = output; stream.dst_size = target.count
                stream.src_ptr = input; stream.src_size = source.count
                while true {
                    let beforeSource = stream.src_size, beforeTarget = stream.dst_size
                    let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                    if status == COMPRESSION_STATUS_END {
                        return stream.src_size == 0 && target.count - stream.dst_size == size
                    }
                    guard status == COMPRESSION_STATUS_OK, stream.dst_size > 0,
                          stream.src_size < beforeSource || stream.dst_size < beforeTarget else { return false }
                }
            }
        }
        guard valid else { throw Failure.invalid }
        bytes.removeLast()
        return bytes
    }
}
