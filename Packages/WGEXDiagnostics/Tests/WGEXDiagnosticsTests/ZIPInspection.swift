// SPDX-License-Identifier: MIT
import Foundation
import Testing

/// Independent test reader: checks stored headers, CRC, central records and EOCD.
package enum ZIPInspection {
    package static func entries(_ data: Data) throws -> [String: Data] {
        let bytes = Array(data)
        var cursor = 0
        var result: [String: Data] = [:]
        var offsets: [Int] = []
        while read(bytes, cursor, 4) == 0x0403_4B50 {
            #expect(read(bytes, cursor + 8, 2) == 0)
            #expect(read(bytes, cursor + 10, 2) == 0)
            #expect(read(bytes, cursor + 12, 2) == 33)
            let size = read(bytes, cursor + 18, 4)
            #expect(size == read(bytes, cursor + 22, 4))
            let nameCount = read(bytes, cursor + 26, 2)
            let start = cursor + 30 + nameCount + read(bytes, cursor + 28, 2)
            try #require(start + size <= bytes.count)
            let name = String(decoding: bytes[cursor + 30 ..< cursor + 30 + nameCount], as: UTF8.self)
            let body = Data(bytes[start ..< start + size])
            #expect(UInt32(read(bytes, cursor + 14, 4)) == independentCRC(body))
            result[name] = body; offsets.append(cursor); cursor = start + size
        }
        let centralStart = cursor
        for offset in offsets {
            #expect(read(bytes, cursor, 4) == 0x0201_4B50)
            #expect(read(bytes, cursor + 42, 4) == offset)
            cursor += 46 + read(bytes, cursor + 28, 2) + read(bytes, cursor + 30, 2) + read(bytes, cursor + 32, 2)
        }
        #expect(read(bytes, cursor, 4) == 0x0605_4B50)
        #expect(read(bytes, cursor + 8, 2) == offsets.count)
        #expect(read(bytes, cursor + 12, 4) == cursor - centralStart)
        #expect(read(bytes, cursor + 16, 4) == centralStart)
        #expect(cursor + 22 == bytes.count)
        return result
    }

    private static func read(_ bytes: [UInt8], _ offset: Int, _ count: Int) -> Int {
        guard offset >= 0, offset + count <= bytes.count else { return -1 }
        return (0 ..< count).reduce(0) { $0 | Int(bytes[offset + $1]) << ($1 * 8) }
    }

    private static func independentCRC(_ data: Data) -> UInt32 {
        var crc = UInt32.max
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0 ..< 8 {
                crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return ~crc
    }

    #if os(macOS)
        package static func checkWithUnzip(_ data: Data) throws {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-zip-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let file = directory.appendingPathComponent("test.zip")
            try data.write(to: file)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
            process.arguments = ["-t", file.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            #expect(process.terminationStatus == 0)
        }
    #endif
}
