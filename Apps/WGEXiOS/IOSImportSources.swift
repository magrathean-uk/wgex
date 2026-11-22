// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import WGEXProfileStore

/// Bounded, in-memory source decoding for the iOS add menu. Archives are never extracted to disk.
internal nonisolated enum IOSImportSources {
    /// Largest accepted file or archive: the archive reader's own bound (DEC-010).
    internal static let maximumBytes = ZipArchiveReader.maximumBytes
    /// A single configuration (a plain `.conf`, a QR payload or a pasted text) is capped at the parser's byte limit.
    internal static let maximumConfigurationBytes = ZipArchiveReader.maximumEntryBytes
    /// Payload-free failures shared with the archive reader.
    internal typealias Failure = ZipArchiveReader.Failure

    #if DEBUG || WGEX_LAB_BUILD
        /// Test seam: when set, every archive scan (including the app's import path) reports its payload accounting here.
        internal nonisolated(unsafe) static var accounting: ZipArchiveReader.Accounting?
    #endif

    private static var scanAccounting: ZipArchiveReader.Accounting? {
        #if DEBUG || WGEX_LAB_BUILD
            accounting
        #else
            nil
        #endif
    }

    /// The folder iOS copies a document opened from another app into (Open In, share sheet), inside the app's own container.
    internal static var inboxDirectory: URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Inbox", isDirectory: true)
    }

    /// Deletes the copy iOS staged in the app container, whether the import worked or not. Files picked from outside it are left alone.
    internal static func removeStagedCopy(_ url: URL) {
        guard url.isFileURL, let inbox = inboxDirectory?.resolvingSymlinksInPath().pathComponents else { return }
        let file = url.resolvingSymlinksInPath()
        let parts = file.pathComponents
        guard parts.count > inbox.count, Array(parts.prefix(inbox.count)) == inbox else { return }
        try? FileManager.default.removeItem(at: file)
    }

    /// Whether the data starts like a local-file or empty ZIP record, whatever its file name says.
    internal static func isArchive(_ data: Data) -> Bool {
        let head = [UInt8](data.prefix(4))
        return head == [0x50, 0x4B, 0x03, 0x04] || head == [0x50, 0x4B, 0x05, 0x06]
    }

    /// Reads a picked or opened file. The size is checked before any byte is read.
    internal static func load(_ url: URL) throws -> Data {
        let access = url.startAccessingSecurityScopedResource()
        defer {
            if access {
                url.stopAccessingSecurityScopedResource()
            }
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= maximumBytes else { throw Failure.tooLarge }
        return try Data(contentsOf: url)
    }

    /// Streams configuration entries to `visit` one at a time; the caller parses and wipes each payload in place.
    internal static func scan(_ data: Data, visit: (String, inout [UInt8]) throws -> Void) throws {
        try ZipArchiveReader.scan(data, accounting: scanAccounting, visit: visit)
    }

    /// True when a scanned payload is plausibly a WireGuard configuration (it has an interface section).
    internal static func looksLikeConfiguration(_ bytes: [UInt8]) -> Bool {
        let marker = Array("[interface]".utf8)
        guard bytes.count >= marker.count else { return false }
        func lower(_ byte: UInt8) -> UInt8 {
            (65 ... 90).contains(byte) ? byte + 32 : byte
        }
        for start in 0 ... bytes.count - marker.count {
            var matches = true
            for offset in 0 ..< marker.count where lower(bytes[start + offset]) != marker[offset] {
                matches = false; break
            }
            if matches {
                return true
            }
        }
        return false
    }
}
