// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal

import Darwin
import Foundation
import WGEXCore
import WGEXProfileStore

/// Writes every tunnel into one .zip in the official app's layout: flat `<name>.conf` entries, nothing else.
///
/// Key handling matches the single-profile export: each configuration is a `SecretText` that is checksummed and
/// written from its locked buffer, one at a time, so no Foundation `Data` or `String` ever holds key material. The
/// file is created beside the destination with 0600 from creation and atomically renamed into place.
internal nonisolated enum IOSTunnelArchive {
    /// The archive must stay importable by `ZipArchiveReader`, so its limits are the writer's limits.
    internal static let maximumEntries = ZipArchiveReader.maximumEntries
    internal static let maximumBytes = ZipArchiveReader.maximumBytes
    internal static let maximumEntryBytes = ParseLimits.default.maximumBytes
    /// Payload-free failures; nothing here carries a name or key byte.
    internal enum Failure: Error, Sendable, Equatable { case empty, tooManyTunnels, tooLarge, writeFailed }

    /// One finished entry's internal record for the central directory.
    private struct Record {
        let name: [UInt8]
        let nameLength: UInt16
        let crc: UInt32
        let size: UInt32
        let offset: UInt32
    }

    /// A whole entry name, `.conf` included, never exceeds this many UTF-8 bytes: the common file system limit, and far
    /// below the ZIP format's 16-bit name length.
    internal static let maximumNameBytes = 255
    private static let suffix = ".conf"

    /// Official naming: `<name>.conf`, with a number when the name is empty, already taken or has no room left.
    /// Path separators and control characters become `_` so every entry stays a flat file when extracted. A long name
    /// is cut on a grapheme boundary to fit `maximumNameBytes`; a name whose first grapheme alone does not fit, or
    /// that collides after the cut, takes the next free number.
    internal static func entryNames(for names: [String]) -> [String] {
        var used = Set<String>()
        var counter = 1
        var result: [String] = []
        let room = maximumNameBytes - suffix.utf8.count
        for name in names {
            let clean = String(name.unicodeScalars.map { scalar in
                scalar == "/" || scalar == "\\" || scalar.value < 0x20 || scalar.value == 0x7F ? "_" : Character(scalar)
            })
            let stem = cut(clean, toBytes: room)
            var file = stem.isEmpty ? "" : stem + suffix
            while file.isEmpty || used.contains(file.lowercased()) {
                file = "\(counter)\(suffix)"; counter += 1
            }
            used.insert(file.lowercased())
            result.append(file)
        }
        return result
    }

    /// The longest run of whole graphemes from the start of `text` that fits in `limit` UTF-8 bytes.
    private static func cut(_ text: String, toBytes limit: Int) -> String {
        var stem = ""
        var bytes = 0
        for character in text {
            let width = character.utf8.count
            guard bytes + width <= limit else { break }
            stem.append(character); bytes += width
        }
        return stem
    }

    /// Writes `count` configurations; `names[i]` labels `text(i)`. Returns the destination, with `.zip` appended when absent.
    /// `byteLimit` is the importer's total bound; only tests pass a smaller one.
    @discardableResult
    internal static func write(
        names: [String], to selectedURL: URL, byteLimit: Int = maximumBytes, text: (Int) async throws -> SecretText,
    ) async throws -> URL {
        guard !names.isEmpty else { throw Failure.empty }
        guard names.count <= maximumEntries else { throw Failure.tooManyTunnels }
        guard selectedURL.isFileURL else { throw Failure.writeFailed }
        let destination = selectedURL.pathExtension.lowercased() == "zip" ? selectedURL : selectedURL.appendingPathExtension("zip")
        let files = entryNames(for: names).map { Array($0.utf8) }
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(".wgex-\(UUID().uuidString)")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw Failure.writeFailed }
        defer { close(descriptor); unlink(temporary.path) }
        guard fchmod(descriptor, mode_t(0o600)) == 0 else { throw Failure.writeFailed }

        var records: [Record] = []
        var offset = 0
        for (index, name) in files.enumerated() {
            let secret = try await text(index)
            let record = try writeEntry(name, secret: secret, at: offset, byteLimit: byteLimit, to: descriptor)
            records.append(record)
            offset += 30 + name.count + Int(record.size)
        }

        let central = centralDirectory(records)
        guard offset + central.count + 22 <= byteLimit,
              let end = endRecord(entries: records.count, centralSize: central.count, centralOffset: offset)
        else { throw Failure.tooLarge }
        try central.withUnsafeBytes { try writeAll(descriptor, $0) }
        try end.withUnsafeBytes { try writeAll(descriptor, $0) }
        guard fsync(descriptor) == 0, rename(temporary.path, destination.path) == 0 else { throw Failure.writeFailed }
        return destination
    }

    private static let utf8Flag = UInt16(0x0800)
    /// 1980-01-01 00:00:00: no clock reading or time zone leaves the device in the archive.
    private static let dosTime = UInt16(0)
    private static let dosDate = UInt16(33)

    /// Writes one local header and its configuration, checking every length before it is narrowed to a ZIP field.
    private static func writeEntry(
        _ name: [UInt8], secret: borrowing SecretText, at offset: Int, byteLimit: Int, to descriptor: Int32,
    ) throws -> Record {
        guard let nameLength = UInt16(exactly: name.count) else { throw Failure.writeFailed }
        let size = secret.byteCount
        guard size <= maximumEntryBytes,
              offset + 30 + name.count + size <= byteLimit,
              let size32 = UInt32(exactly: size), let offset32 = UInt32(exactly: offset)
        else { throw Failure.tooLarge }
        let crc = secret.bytes.withUnsafeBytes { CRC32.checksum($0) }
        let header = localHeader(name: name, nameLength: nameLength, crc: crc, size: size32)
        try header.withUnsafeBytes { try writeAll(descriptor, $0) }
        try secret.bytes.withUnsafeBytes { try writeAll(descriptor, $0) }
        return Record(name: name, nameLength: nameLength, crc: crc, size: size32, offset: offset32)
    }

    private static func localHeader(name: [UInt8], nameLength: UInt16, crc: UInt32, size: UInt32) -> [UInt8] {
        var header = [UInt8]()
        header.reserveCapacity(30 + name.count)
        header.appendLE(UInt32(0x0403_4B50)); header.appendLE(UInt16(20)); header.appendLE(utf8Flag)
        header.appendLE(UInt16(0)); header.appendLE(dosTime); header.appendLE(dosDate)
        header.appendLE(crc); header.appendLE(size); header.appendLE(size)
        header.appendLE(nameLength); header.appendLE(UInt16(0)); header.append(contentsOf: name)
        return header
    }

    /// The end-of-central-directory record; nil when a count or offset does not fit its ZIP field.
    private static func endRecord(entries: Int, centralSize: Int, centralOffset: Int) -> [UInt8]? {
        guard let count = UInt16(exactly: entries), let size = UInt32(exactly: centralSize),
              let offset = UInt32(exactly: centralOffset)
        else { return nil }
        var end = [UInt8]()
        end.appendLE(UInt32(0x0605_4B50)); end.appendLE(UInt16(0)); end.appendLE(UInt16(0))
        end.appendLE(count); end.appendLE(count)
        end.appendLE(size); end.appendLE(offset); end.appendLE(UInt16(0))
        return end
    }

    private static func centralDirectory(_ records: [Record]) -> [UInt8] {
        var central = [UInt8]()
        for record in records {
            central.appendLE(UInt32(0x0201_4B50)); central.appendLE(UInt16(0x0314)); central.appendLE(UInt16(20))
            central.appendLE(utf8Flag); central.appendLE(UInt16(0)); central.appendLE(dosTime); central.appendLE(dosDate)
            central.appendLE(record.crc); central.appendLE(record.size); central.appendLE(record.size)
            central.appendLE(record.nameLength); central.appendLE(UInt16(0)); central.appendLE(UInt16(0))
            central.appendLE(UInt16(0)); central.appendLE(UInt16(0))
            // Unix regular file, mode 0600, so extraction keeps the keys private.
            central.appendLE(UInt32(0o100600) << 16); central.appendLE(record.offset)
            central.append(contentsOf: record.name)
        }
        return central
    }

    private static func writeAll(_ descriptor: Int32, _ raw: UnsafeRawBufferPointer) throws {
        var written = 0
        while written < raw.count {
            let count = Darwin.write(descriptor, raw.baseAddress?.advanced(by: written), raw.count - written)
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { throw Failure.writeFailed }
            written += count
        }
    }
}

private nonisolated extension [UInt8] {
    mutating func appendLE(_ value: some FixedWidthInteger) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }
}
