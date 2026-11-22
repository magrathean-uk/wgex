// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    /// Planted key material in every field a log source returns never reaches the view's lines, the saved file or the
    /// rendered text; the buffer and one read are bounded; Save writes only the chosen file.
    @MainActor
    private struct MacLogTests {
        private struct PlantedKeys {
            let privateKey: [UInt8]
            let presharedKey: [UInt8]

            init() {
                privateKey = (0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) }
                presharedKey = (0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) }
            }

            static func base64(_ key: [UInt8]) -> String {
                Data(key).base64EncodedString()
            }

            static func base64URL(_ key: [UInt8]) -> String {
                base64(key).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            }

            static func hex(_ key: [UInt8]) -> String {
                key.map { String(format: "%02x", $0) }.joined()
            }

            /// Every textual shape of both keys, alone, in assignments, glued to text and as a 42-character fragment.
            var shapes: [String] {
                [privateKey, presharedKey].flatMap { key in
                    [
                        Self.base64(key), Self.base64URL(key), Self.hex(key), "PrivateKey = \(Self.base64(key))",
                        "PresharedKey=\(Self.base64(key))", "peer(\(Self.base64(key)))", "key:\(Self.base64(key)).",
                        String(Self.base64(key).prefix(42)),
                    ]
                }
            }

            /// Distinctive substrings that must not survive.
            var fragments: [String] {
                [privateKey, presharedKey].flatMap { key in
                    [String(Self.base64(key).dropFirst(8).prefix(16)), String(Self.hex(key).dropFirst(8).prefix(24))]
                }
            }

            var scanner: SecretScanner {
                var scanner = SecretScanner()
                for key in [privateKey, presharedKey] {
                    key.withUnsafeBytes { raw in
                        if let bytes = try? SecretBytes(copying: raw) {
                            scanner.register(bytes)
                        }
                    }
                }
                return scanner
            }

            func assertAbsent(from text: String, sourceLocation: SourceLocation = #_sourceLocation) {
                #expect(scanner.isClean(text), sourceLocation: sourceLocation)
                for fragment in fragments {
                    #expect(!text.contains(fragment), sourceLocation: sourceLocation)
                }
            }
        }

        private static let start = Date(timeIntervalSince1970: 1_800_000_000)

        private func plantedLines(_ keys: PlantedKeys) -> [MacLogLine] {
            keys.shapes.enumerated().flatMap { index, shape in
                let date = Self.start.addingTimeInterval(Double(index))
                return [
                    MacLogLine(date: date, category: "engine", message: "Received handshake \(shape) from peer"),
                    MacLogLine(date: date, category: "daemon \(shape)", message: "Tunnel status changed"),
                    MacLogLine(date: date, category: "engine", message: shape),
                    // Longer than the per-line bound, with the key at the cut.
                    MacLogLine(
                        date: date,
                        category: "engine",
                        message: String(repeating: ".", count: MacLogBuffer.messageLimit - 20) + " " + shape,
                    ),
                ]
            }
        }

        @Test func `planted private and preshared keys never reach the view, the saved file or a rendered line`() async throws {
            let keys = PlantedKeys()
            let planted = plantedLines(keys)
            // The source itself would leak: the test is meaningful only if the scanner sees the planted keys.
            #expect(!keys.scanner.isClean(planted.map { $0.category + $0.message }.joined(separator: "\n")))
            let log = MacActivityLog { _ in planted }
            await log.refresh()
            #expect(log.available)
            #expect(log.buffer.entries.count == planted.count)
            for line in log.buffer.lines {
                keys.assertAbsent(from: line.category)
                keys.assertAbsent(from: line.message)
                keys.assertAbsent(from: MacLogBuffer.render(line))
            }
            keys.assertAbsent(from: log.buffer.text)
            #expect(log.buffer.text.contains(MacLogRedaction.replacement))
            #expect(log.buffer.text.contains("Received handshake"))

            let directory = FileManager.default.temporaryDirectory.appending(path: "wgex-log-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let chosen = directory.appending(path: MacLogFile.suggestedName(at: Self.start))
            try log.save(to: chosen)
            let saved = try String(contentsOf: chosen, encoding: .utf8)
            keys.assertAbsent(from: saved)
            #expect(saved == log.buffer.text)
            // Only the chosen file exists; the atomic write leaves no temporary beside it.
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [chosen.lastPathComponent])
        }

        @Test func `the scrub removes every key shape and keeps ordinary text`() {
            let keys = PlantedKeys()
            for shape in keys.shapes {
                let scrubbed = MacLogRedaction.scrub("before \(shape) after")
                keys.assertAbsent(from: scrubbed)
                #expect(scrubbed.hasPrefix("before "))
            }
            let ordinary = "Interface up, MTU 1280, handshake at 12:00:01 with 192.0.2.1:51820"
            #expect(MacLogRedaction.scrub(ordinary) == ordinary)
        }

        @Test func `the view holds a bounded log and reads on from its cursor without repeats`() async {
            let cursors = Mutex<[Date?]>([])
            let batch = (0 ..< 3000).map {
                MacLogLine(date: Self.start.addingTimeInterval(Double($0)), category: "engine", message: "line \($0)")
            }
            let log = MacActivityLog { since in
                cursors.withLock { $0.append(since) }
                // A source returns lines at the cursor again; the buffer must not repeat them.
                return since.map { since in batch.filter { $0.date >= since } } ?? batch
            }
            await log.refresh()
            #expect(log.buffer.entries.count == MacLogBuffer.capacity)
            #expect(log.buffer.lines.last?.message == "line 2999")
            #expect(log.buffer.lines.first?.message == "line 1000")
            await log.refresh()
            #expect(log.buffer.entries.count == MacLogBuffer.capacity)
            #expect(cursors.withLock { $0 } == [nil, batch.last?.date])

            var buffer = MacLogBuffer()
            buffer.merge([MacLogLine(date: Self.start, category: "engine", message: String(repeating: ".", count: 5000))])
            #expect(buffer.lines.first?.message.count == MacLogBuffer.messageLimit)
            // A new line at the same instant is kept; a repeated one is not.
            let added = buffer.merge([MacLogLine(date: Self.start, category: "engine", message: "same instant")])
            let repeated = buffer.merge([MacLogLine(date: Self.start, category: "engine", message: "same instant")])
            #expect(added)
            #expect(!repeated)
            #expect(buffer.entries.count == 2)
        }

        @Test func `a failed read marks the log unavailable and keeps held lines`() async {
            struct Unavailable: Error {}
            let fail = Mutex(false)
            let log = MacActivityLog { _ in
                if fail.withLock({ $0 }) {
                    throw Unavailable()
                }
                return [MacLogLine(date: Self.start, category: "daemon", message: "Tunnel status changed")]
            }
            await log.refresh()
            #expect(log.available)
            fail.withLock { $0 = true }
            await log.refresh()
            #expect(!log.available)
            #expect(log.buffer.entries.count == 1)
            let unsupported = MacActivityLog(read: MacShellOperations().readLog)
            await unsupported.refresh()
            #expect(!unsupported.available)
        }

        @Test func `a failed save throws and writes nothing`() {
            let log = MacActivityLog { _ in [] }
            let missing = FileManager.default.temporaryDirectory.appending(path: "wgex-missing-\(UUID().uuidString)/log.txt")
            #expect(throws: (any Error).self) { try log.save(to: missing) }
            #expect(!FileManager.default.fileExists(atPath: missing.path))
        }

        @Test func `the suggested name is a txt file and the Log page reads only while Raw is shown`() throws {
            let name = MacLogFile.suggestedName(at: Self.start)
            #expect(name.hasPrefix("WGEX Log "))
            #expect(name.hasSuffix(".txt"))
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
            let view = try String(
                contentsOf: root.appending(path: "Sources/WGEXUI/Screens/Mac/MacLogPage.swift"),
                encoding: .utf8,
            )
            #expect(view.contains(".task(id: showsRaw)"))
            #expect(view.contains("guard showsRaw else { return }"))
            #expect(view.contains("await log.refresh()"))
            #expect(view.contains("panel.allowedContentTypes = [.plainText]"))
            #expect(view.contains("try MacAppPagesPresentation.saveLog(text, to: url)"))
            #expect(view.contains("model.operationMessage = MacStrings.theLogCouldNotBeSaved"))
            #expect(!view.contains("MacLogFile.write"))
        }
    }
#endif
