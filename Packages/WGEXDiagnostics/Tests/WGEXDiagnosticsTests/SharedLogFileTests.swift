// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDiagnostics

private struct SharedLogFileTests {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "sharedlog-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test
    func `two writers interleave without losing or tearing lines`() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = SharedLogFile(directory: dir)
        let tunnel = SharedLogFile(directory: dir)
        await withTaskGroup(of: Void.self) { group in
            group.addTask { for index in 0 ..< 150 {
                app.append("a\(index)", process: .app)
            } }
            group.addTask { for index in 0 ..< 150 {
                tunnel.append("t\(index)", process: .tunnel)
            } }
        }
        let entries = app.read()
        #expect(entries.count == 300)
        #expect(entries.filter { $0.process == .app }.map(\.message) == (0 ..< 150).map { "a\($0)" })
        #expect(entries.filter { $0.process == .tunnel }.map(\.message) == (0 ..< 150).map { "t\($0)" })
    }

    @Test
    func `reads in time order`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir)
        log.append("late", process: .app, date: Date(timeIntervalSince1970: 200))
        log.append("early", process: .tunnel, date: Date(timeIntervalSince1970: 100))
        #expect(log.read().map(\.message) == ["early", "late"])
    }

    @Test
    func `cap evicts whole oldest lines`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir, capBytes: 4000)
        for index in 0 ..< 200 {
            log.append(
                "line \(index) " + String(repeating: "x", count: 80),
                process: .app,
                date: Date(timeIntervalSince1970: Double(index)),
            )
        }
        let size = try #require(FileManager.default.attributesOfItem(atPath: log.url.path)[.size] as? Int)
        #expect(size <= 4000)
        let entries = log.read()
        #expect(entries.last?.message.hasPrefix("line 199 ") == true)
        #expect(entries.first.map { $0.message.hasPrefix("line ") } == true)
        let numbers = entries.compactMap { Int($0.message.split(separator: " ")[1]) }
        #expect(numbers == Array(numbers[0] ... 199))
        #expect(entries.allSatisfy { $0.message.hasSuffix("xxxx") })
    }

    @Test
    func `the log stays 0600 after an eviction`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let previous = umask(0o022)
        defer { umask(previous) }
        let log = SharedLogFile(directory: dir, capBytes: 4000)
        for index in 0 ..< 100 {
            log.append("line \(index) " + String(repeating: "x", count: 80), process: .app)
        }
        let size = try #require(FileManager.default.attributesOfItem(atPath: log.url.path)[.size] as? Int)
        #expect(size < 4000)
        let mode = try #require(FileManager.default.attributesOfItem(atPath: log.url.path)[.posixPermissions] as? Int)
        #expect(mode == 0o600)
    }

    @Test
    func `private and preshared keys are redacted in base64, base64url and hex`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir)
        let bytes = (0 ..< 32).map { UInt8(($0 * 17 + 29) % 256) }
        let key = Data(bytes).base64EncodedString()
        let urlKey = key.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = bytes.reversed().map { String(format: "%02x", $0) }.joined()
        log.append("PrivateKey = \(key)", process: .app)
        log.append("PresharedKey = \(key)", process: .tunnel)
        log.append("relay \(urlKey)", process: .tunnel)
        log.append("private_key=\(hex)", process: .tunnel)
        let raw = try String(contentsOf: log.url, encoding: .utf8)
        for secret in [key, String(urlKey.prefix(22)), hex] {
            #expect(!raw.contains(secret))
            #expect(!String(decoding: log.export(), as: UTF8.self).contains(secret))
        }
    }

    @Test
    func `an over-long line is cut after redaction, never inside a key`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir)
        let key = Data((0 ..< 32).map { UInt8($0 * 7 + 3) }).base64EncodedString()
        // 30 bytes of room: the raw key would put 30 of its characters inside the cut.
        log.append(String(repeating: ".", count: SharedLogFile.maxLineBytes - 30) + key, process: .app)
        let raw = try String(contentsOf: log.url, encoding: .utf8)
        #expect(!raw.contains(String(key.prefix(16))))
        #expect(raw.contains("<secret:"))
    }

    @Test
    func `export has a UTC header and tagged lines`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir)
        log.append("multi\nline", process: .tunnel, date: Date(timeIntervalSince1970: 0))
        let text = String(decoding: log.export(now: Date(timeIntervalSince1970: 86400)), as: UTF8.self)
        #expect(text.hasPrefix("# WGEX shared log exported 1970-01-02T00:00:00.000Z\n"))
        #expect(text.contains("1970-01-01T00:00:00.000Z [tunnel] multi\nline\n"))
    }

    @Test
    func `missing, corrupt and unwritable locations recover without throwing`() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = SharedLogFile(directory: dir)
        #expect(log.read().isEmpty)
        try Data([0xFF, 0xFE, 0x00, 0x0A, 0x31, 0x09, 0x61]).write(to: log.url)
        #expect(log.read().isEmpty)
        #expect(log.append("after corrupt", process: .app))
        #expect(log.read().map(\.message) == ["after corrupt"])
        let missing = SharedLogFile(directory: dir.appending(path: "nope/deeper"))
        #expect(missing.append("x", process: .app) == false)
        #expect(missing.read().isEmpty)
        #expect(!missing.export().isEmpty)
    }
}
