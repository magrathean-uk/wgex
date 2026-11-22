// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXProfileStore

    /// Bounded, in-memory source decoding. Archives are never extracted to disk.
    public nonisolated enum MacImportSources {
        public static let maximumBytes = ZipArchiveReader.maximumBytes
        /// Shared, payload-free failures for file and archive sources.
        public typealias Failure = ZipArchiveReader.Failure

        /// Test seam: when set, every archive scan (including the app's import path) reports its payload accounting here.
        public nonisolated(unsafe) static var accounting: ZipArchiveReader.Accounting?

        /// Streams configuration entries to `visit` one at a time; the caller parses and wipes each payload in place.
        public static func scan(_ data: Data, visit: (String, inout [UInt8]) throws -> Void) throws {
            try ZipArchiveReader.scan(data, accounting: accounting, visit: visit)
        }

        public static func archive(_ data: Data) throws -> [(String, [UInt8])] {
            try ZipArchiveReader.archive(data)
        }
    }
#endif
