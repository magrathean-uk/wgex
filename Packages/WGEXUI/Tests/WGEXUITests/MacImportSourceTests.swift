// SPDX-License-Identifier: MIT

#if os(macOS)
    import Compression
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXUI

    @MainActor
    private struct MacImportSourceTests {
        /// Public, non-configuration fixture data. No keys or real endpoints.
        private nonisolated static let stored = Data(
            "50 4b 03 04 14 00 00 00 00 00 c5 be 59 5d eb 33 fa 55 0c 00 00 00 0c 00 00 00 13 00 00 00 6e 65 73 74 65 64 2f 46 69 78 74 75 72 65 2e 63 6f 6e 66 66 69 78 74 75 72 65 20 64 61 74 61 50 4b 03 04 14 00 00 00 00 00 c5 be 59 5d e2 d6 88 0d 06 00 00 00 06 00 00 00 0b 00 00 00 69 67 6e 6f 72 65 64 2e 74 78 74 69 67 6e 6f 72 65 50 4b 01 02 14 03 14 00 00 00 00 00 c5 be 59 5d eb 33 fa 55 0c 00 00 00 0c 00 00 00 13 00 00 00 00 00 00 00 00 00 00 00 80 01 00 00 00 00 6e 65 73 74 65 64 2f 46 69 78 74 75 72 65 2e 63 6f 6e 66 50 4b 01 02 14 03 14 00 00 00 00 00 c5 be 59 5d e2 d6 88 0d 06 00 00 00 06 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00 80 01 3d 00 00 00 69 67 6e 6f 72 65 64 2e 74 78 74 50 4b 05 06 00 00 00 00 02 00 02 00 7a 00 00 00 6c 00 00 00 00 00"
                .split(separator: " ").compactMap { UInt8(
                    $0,
                    radix: 16,
                ) },
        )
        private nonisolated static let deflated = Data(
            "50 4b 03 04 14 00 00 00 08 00 c5 be 59 5d eb 33 fa 55 0e 00 00 00 0c 00 00 00 13 00 00 00 6e 65 73 74 65 64 2f 46 69 78 74 75 72 65 2e 63 6f 6e 66 4b cb ac 28 29 2d 4a 55 48 49 2c 49 04 00 50 4b 03 04 14 00 00 00 08 00 c5 be 59 5d e2 d6 88 0d 08 00 00 00 06 00 00 00 0b 00 00 00 69 67 6e 6f 72 65 64 2e 74 78 74 cb 4c cf cb 2f 4a 05 00 50 4b 01 02 14 03 14 00 00 00 08 00 c5 be 59 5d eb 33 fa 55 0e 00 00 00 0c 00 00 00 13 00 00 00 00 00 00 00 00 00 00 00 80 01 00 00 00 00 6e 65 73 74 65 64 2f 46 69 78 74 75 72 65 2e 63 6f 6e 66 50 4b 01 02 14 03 14 00 00 00 08 00 c5 be 59 5d e2 d6 88 0d 08 00 00 00 06 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00 80 01 3f 00 00 00 69 67 6e 6f 72 65 64 2e 74 78 74 50 4b 05 06 00 00 00 00 02 00 02 00 7a 00 00 00 70 00 00 00 00 00"
                .split(separator: " ").compactMap { UInt8(
                    $0,
                    radix: 16,
                ) },
        )

        @Test(arguments: [stored, deflated])
        func `archives decode configurations in memory and use only the filename`(_ data: Data) throws {
            let entries = try MacImportSources.archive(data)
            #expect(entries.count == 1)
            let entry = try #require(entries.first)
            #expect(entry.0 == "Fixture")
            #expect(String(decoding: entry.1, as: UTF8.self) == "fixture data")
        }

        @Test func `archive checksum corruption is rejected`() {
            var data = Self.stored
            data[49] ^= 0xFF
            #expect(throws: MacImportSources.Failure.self) { try MacImportSources.archive(data) }
        }

        @Test(arguments: [Data(), Data(repeating: 0, count: 64), Data(repeating: 0, count: MacImportSources.maximumBytes + 1)])
        func `malformed or oversized archives are rejected`(_ data: Data) {
            #expect(throws: MacImportSources.Failure.self) { try MacImportSources.archive(data) }
        }

        // MARK: bounded memory through the production import path

        /// A valid archive of `count` deflated entries whose payloads each decode to `size` bytes.
        private nonisolated static func limitArchive(count: Int, size: Int) -> Data {
            // One long comment line: the parser must still read every byte, but never builds field values.
            let body = [UInt8](repeating: 35, count: size)
            var crc = UInt32.max
            for byte in body {
                crc ^= UInt32(byte)
                for _ in 0 ..< 8 {
                    crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xEDB8_8320
                }
            }
            crc = ~crc
            var packed = [UInt8](repeating: 0, count: size)
            let used = compression_encode_buffer(&packed, size, body, size, nil, COMPRESSION_ZLIB)
            packed.removeSubrange(used...)
            var local = Data(), central = Data()
            func u16(_ value: Int, _ data: inout Data) {
                data.append(UInt8(truncatingIfNeeded: value)); data.append(UInt8(truncatingIfNeeded: value >> 8))
            }
            func u32(_ value: Int, _ data: inout Data) {
                u16(value & 0xFFFF, &data); u16((value >> 16) & 0xFFFF, &data)
            }
            for index in 0 ..< count {
                let name = Array("T\(index).conf".utf8), offset = local.count
                u32(0x0403_4B50, &local); u16(20, &local); u16(0, &local); u16(8, &local); u32(0, &local)
                u32(Int(crc), &local); u32(used, &local); u32(size, &local); u16(name.count, &local); u16(0, &local)
                local.append(contentsOf: name); local.append(contentsOf: packed)
                u32(0x0201_4B50, &central); u16(20, &central); u16(20, &central); u16(0, &central); u16(8, &central)
                u32(0, &central); u32(Int(crc), &central); u32(used, &central); u32(size, &central)
                u16(name.count, &central); u16(0, &central); u16(0, &central); u16(0, &central); u16(0, &central)
                u32(0, &central); u32(offset, &central); central.append(contentsOf: name)
            }
            let start = local.count; local.append(central)
            u32(0x0605_4B50, &local); u16(0, &local); u16(0, &local)
            u16(count, &local); u16(count, &local)
            u32(central.count, &local); u32(start, &local); u16(0, &local)
            return local
        }

        /// Imports a `count` by `size` archive through `importURLs` and asserts review count and payload accounting.
        private static func importAtLimits(count: Int, size: Int) throws -> Data {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let zip = root.appendingPathComponent("limit.zip")
            let archive = limitArchive(count: count, size: size)
            try archive.write(to: zip)

            let accounting = ZipArchiveReader.Accounting()
            MacImportSources.accounting = accounting
            defer { MacImportSources.accounting = nil }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root)
            app.importURLs([zip])
            MacImportSources.accounting = nil
            #expect(app.importReviews.count == count)
            #expect(accounting.peak == size)
            #expect(accounting.live == 0)
            #expect(accounting.retained == 0)
            #expect(accounting.unwiped == 0)
            return archive
        }

        /// Both DEC-010 limits at once: 1,024 entries of 256 KiB (256 MiB). The scan, in-place parse and wipe run off the
        /// main actor (a `nonisolated` test), so this multi-second job cannot starve the main-actor timing tests that run
        /// in parallel; the app's own `importURLs` is exercised at each limit separately in the test below.
        @Test func `a combined-limit archive scans with one entry in flight`() async {
            // A dedicated thread, not the cooperative pool or the main actor, so the scan cannot starve other tests.
            let failures: [String] = await withCheckedContinuation { continuation in
                Thread.detachNewThread { continuation.resume(returning: Self.combinedLimitFailures()) }
            }
            #expect(failures.isEmpty, "\(failures)")
        }

        private nonisolated static func combinedLimitFailures() -> [String] {
            let count = ZipArchiveReader.maximumEntries, size = ZipArchiveReader.maximumEntryBytes
            let archive = limitArchive(count: count, size: size)
            let accounting = ZipArchiveReader.Accounting()
            var reviews = 0
            do {
                // The same per-entry work as the app's `makeReview`: parse in place, then wipe the payload.
                try ZipArchiveReader.scan(archive, accounting: accounting) { name, bytes in
                    defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
                    _ = try? parseWgQuick(&bytes, name: name) // a parse error still yields a review in the app
                    reviews += 1
                }
            } catch { return ["scan threw \(error)"] }
            let observed = [
                ("reviews", reviews, count), ("peak", accounting.peak, size), ("live", accounting.live, 0),
                ("retained", accounting.retained, 0), ("unwiped", accounting.unwiped, 0),
            ]
            return observed.filter { $0.1 != $0.2 }.map { "\($0.0) \($0.1) expected \($0.2)" }
        }

        /// Archives go through the app's own `importURLs` (scan, in-place parse and wipe, review creation) with the reader's
        /// accounting attached. Peak live payload is exactly one entry, nothing is retained or left unwiped. The import
        /// runs on the main actor; the two DEC-010 limits are exercised separately here (entry count with small entries, entry
        /// size with a few full-size ones) and together, off the main actor, in the combined-limit test above.
        @Test(arguments: [(ZipArchiveReader.maximumEntries, 64), (4, ZipArchiveReader.maximumEntryBytes)])
        func `a limit archive imports through the app with one entry in flight`(count: Int, size: Int) throws {
            let archive = try Self.importAtLimits(count: count, size: size)

            // Controls: a visitor that keeps the payload, and one that parses a private copy and leaves the payload readable.
            let kept = ZipArchiveReader.Accounting()
            var stash: [[UInt8]] = []
            try ZipArchiveReader.scan(archive, accounting: kept) { _, bytes in stash.append(bytes) }
            #expect(kept.peak == count * size)
            #expect(kept.retained == count * size)
            let copied = ZipArchiveReader.Accounting()
            try ZipArchiveReader.scan(archive, accounting: copied) { name, bytes in
                var copy = bytes
                _ = try? parseWgQuick(&copy, name: name)
            }
            #expect(copied.unwiped == count * size)
        }

        @Test func `a bad second entry after a staged review refuses the whole archive`() throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let zip = root.appendingPathComponent("broken.zip")
            let data = Self.twoConfigurations(corruptSecond: true)
            try data.write(to: zip)
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root)
            app.importURLs([zip])
            #expect(app.importReviews.isEmpty)
            #expect(app.shell.operationMessage != nil)
            // The same archive uncorrupted stages both reviews, so the refusal above came after the first was staged.
            let good = root.appendingPathComponent("good.zip")
            try Self.twoConfigurations(corruptSecond: false).write(to: good)
            app.importURLs([good])
            #expect(app.importReviews.count == 2)
        }

        /// Two stored `.conf` entries holding one comment line each; the second payload's first byte is flipped when asked.
        private nonisolated static func twoConfigurations(corruptSecond: Bool) -> Data {
            let body = Array("# fixture\n".utf8)
            var crc = UInt32.max
            for byte in body {
                crc ^= UInt32(byte)
                for _ in 0 ..< 8 {
                    crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xEDB8_8320
                }
            }
            crc = ~crc
            var local = Data(), central = Data()
            func u16(_ value: Int, _ data: inout Data) {
                data.append(UInt8(truncatingIfNeeded: value)); data.append(UInt8(truncatingIfNeeded: value >> 8))
            }
            func u32(_ value: Int, _ data: inout Data) {
                u16(value & 0xFFFF, &data); u16((value >> 16) & 0xFFFF, &data)
            }
            for index in 0 ..< 2 {
                let name = Array("T\(index).conf".utf8), offset = local.count
                u32(0x0403_4B50, &local); u16(20, &local); u16(0, &local); u16(0, &local); u32(0, &local)
                u32(Int(crc), &local); u32(body.count, &local); u32(body.count, &local); u16(name.count, &local); u16(0, &local)
                local.append(contentsOf: name)
                var payload = body
                if corruptSecond, index == 1 {
                    payload[0] ^= 0xFF
                }
                local.append(contentsOf: payload)
                u32(0x0201_4B50, &central); u16(20, &central); u16(20, &central); u16(0, &central); u16(0, &central)
                u32(0, &central); u32(Int(crc), &central); u32(body.count, &central); u32(body.count, &central)
                u16(name.count, &central); u16(0, &central); u16(0, &central); u16(0, &central); u16(0, &central)
                u32(0, &central); u32(offset, &central); central.append(contentsOf: name)
            }
            let start = local.count; local.append(central)
            u32(0x0605_4B50, &local); u16(0, &local); u16(0, &local); u16(2, &local); u16(2, &local)
            u32(central.count, &local); u32(start, &local); u16(0, &local)
            return local
        }
    }
#endif
