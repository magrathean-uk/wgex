// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXProfileStore

private struct ZipArchiveReaderTests {
    @Test
    func `stored entries are memory only and CRC checked`() throws {
        let archive = Self.archive(name: "../../fixture.conf", payload: Array("[Interface]".utf8))
        let entries = try ZipArchiveReader.archive(archive)
        #expect(entries.count == 1)
        #expect(entries.first?.0 == "fixture")
        #expect(entries.first?.1 == Array("[Interface]".utf8))
        var corrupt = archive
        corrupt[30 + "../../fixture.conf".utf8.count] ^= 1
        #expect(throws: ZipArchiveReader.Failure.invalid) { try ZipArchiveReader.archive(corrupt) }
    }

    @Test(arguments: ["stored", "deflate"])
    func `supported compression and traversal names`(_ name: String) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/fuzz/zip/\(name).zip"))
        let entries = try ZipArchiveReader.archive(data)
        #expect(entries.first?.0 == "seed")
        #expect(entries.first?.1 == Array("# fixture with no keys\n[Interface]\n".utf8))
    }

    @Test
    func `input and entry count caps`() {
        #expect(ZipArchiveReader.maximumEntries == 1024)
        #expect(ZipArchiveReader.maximumBytes == ZipArchiveReader.maximumEntries * ParseLimits.default.maximumBytes)
        #expect(throws: ZipArchiveReader.Failure.tooLarge) {
            try ZipArchiveReader.archive(Data(count: ZipArchiveReader.maximumBytes + 1))
        }
        var archive = Self.archive(name: "a.conf", payload: [65])
        // Advertise 1,025 entries: the entry bound plus one.
        archive[archive.count - 12] = 1; archive[archive.count - 11] = 4
        #expect(throws: ZipArchiveReader.Failure.tooLarge) { try ZipArchiveReader.archive(archive) }
    }

    @Test
    func `every truncation throws`() {
        let archive = Self.archive(name: "a.conf", payload: [65])
        for count in 0 ..< archive.count {
            #expect(throws: (any Error).self) { try ZipArchiveReader.archive(Data(archive.prefix(count))) }
        }
    }

    @Test(arguments: [UInt16(1), 6, 9])
    func `unsupported compression methods reject`(_ method: UInt16) {
        let archive = Self.archive(name: "a.conf", payload: [65], method: method)
        #expect(throws: ZipArchiveReader.Failure.unsupported) { try ZipArchiveReader.archive(archive) }
    }

    @Test
    func `parser entry cap is enforced`() {
        let archive = Self.archive(name: "a.conf", payload: Array(repeating: 65, count: ParseLimits.default.maximumBytes + 1))
        #expect(throws: ZipArchiveReader.Failure.tooLarge) { try ZipArchiveReader.archive(archive) }
    }

    @Test
    func `zip 64 and encryption reject`() {
        for field in [6, 18] {
            var archive = Self.archive(name: "a.conf", payload: [65])
            if field == 6 {
                archive[6] = 1; archive[37 + 8] = 1
            } else {
                archive[18 ..< 22] = Data([255, 255, 255, 255]); archive[37 + 20 ..< 37 + 24] = Data([255, 255, 255, 255])
            }
            #expect(throws: ZipArchiveReader.Failure.unsupported) { try ZipArchiveReader.archive(archive) }
        }
    }

    private static func archive(name: String, payload: [UInt8], method: UInt16 = 0) -> Data {
        let nameBytes = Array(name.utf8)
        var result = Data()
        func u16(_ value: UInt16) {
            result.append(UInt8(truncatingIfNeeded: value)); result.append(UInt8(truncatingIfNeeded: value >> 8))
        }
        func u32(_ value: UInt32) {
            u16(UInt16(truncatingIfNeeded: value)); u16(UInt16(truncatingIfNeeded: value >> 16))
        }
        var crc = UInt32.max
        for byte in payload {
            crc ^= UInt32(byte)
            for _ in 0 ..< 8 {
                crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xEDB8_8320
            }
        }
        crc = ~crc
        u32(0x0403_4B50); u16(20); u16(0); u16(method); u16(0); u16(0); u32(crc)
        u32(UInt32(payload.count)); u32(UInt32(payload.count)); u16(UInt16(nameBytes.count)); u16(0)
        result.append(contentsOf: nameBytes); result.append(contentsOf: payload)
        let central = result.count
        u32(0x0201_4B50); u16(20); u16(20); u16(0); u16(method); u16(0); u16(0); u32(crc)
        u32(UInt32(payload.count)); u32(UInt32(payload.count)); u16(UInt16(nameBytes.count)); u16(0); u16(0)
        u16(0); u16(0); u32(0); u32(0); result.append(contentsOf: nameBytes)
        let centralSize = result.count - central
        u32(0x0605_4B50); u16(0); u16(0); u16(1); u16(1); u32(UInt32(centralSize)); u32(UInt32(central)); u16(0)
        return result
    }
}
