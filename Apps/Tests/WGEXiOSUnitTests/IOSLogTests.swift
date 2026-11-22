// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if DEBUG || WGEX_LAB_BUILD
    import Foundation
    import Testing
    @testable import WGEX
    import WGEXCore
    import WGEXDiagnostics

    @MainActor
    private struct IOSLogTests {
        private func model() -> AppModel {
            AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        }

        @Test
        func `app lifecycle and injected extension lines are merged in time order`() async throws {
            let model = model()
            defer { try? FileManager.default.removeItem(at: model.container) }
            let runner = Task { await model.run() }
            defer { runner.cancel() }
            try await until { model.log.file.read().contains { $0.message == "App session started" } }
            // Separate instances stand in for the two processes writing the same App Group file.
            let extensionLog = SharedLogFile(directory: model.container)
            model.log.file.append("App later", process: .app, date: Date(timeIntervalSince1970: 2))
            extensionLog.append("Extension earlier", process: .tunnel, date: Date(timeIntervalSince1970: 1))
            let watcher = Task { await model.watchLog() }
            defer { watcher.cancel() }
            try await until { model.logText.contains("App later") }
            #expect(model.logText.hasPrefix("1970-01-01T00:00:01.000Z [tunnel] Extension earlier\n"))
            #expect(model.logText.contains("1970-01-01T00:00:02.000Z [app] App later\n"))
            runner.cancel()
            await runner.value
            #expect(model.log.file.read().last?.message == "App session ended")
            watcher.cancel()
            await watcher.value
        }

        @Test
        func `open log follows new lines and cancellation stops polling until reopened`() async throws {
            let model = model()
            defer { try? FileManager.default.removeItem(at: model.container) }
            model.log.refreshInterval = .milliseconds(10)
            let extensionLog = SharedLogFile(directory: model.container)
            let watcher = Task { await model.watchLog() }
            defer { watcher.cancel() }
            extensionLog.append("First line", process: .tunnel)
            try await until { model.logText.contains("First line") }
            extensionLog.append("New line", process: .tunnel)
            try await until { model.logText.contains("New line") }
            watcher.cancel()
            await watcher.value
            let snapshot = model.logText
            extensionLog.append("After close", process: .tunnel)
            try await Task.sleep(for: .milliseconds(30))
            #expect(model.logText == snapshot)
            let reopened = Task { await model.watchLog() }
            defer { reopened.cancel() }
            try await until { model.logText.contains("After close") }
            reopened.cancel()
            await reopened.value
        }

        @Test
        func `export has a UTC header and fresh merged content even without an open log`() throws {
            let model = model()
            defer { try? FileManager.default.removeItem(at: model.container) }
            model.log.file.append("App line", process: .app, date: Date(timeIntervalSince1970: 1))
            SharedLogFile(directory: model.container).append("Extension line", process: .tunnel, date: Date(timeIntervalSince1970: 2))
            let text = String(decoding: model.exportLog(), as: UTF8.self)
            let prefix = "# WGEX shared log exported "
            #expect(text.hasPrefix(prefix))
            let header = try #require(text.split(separator: "\n").first)
            let stamp = String(header.dropFirst(prefix.count))
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            #expect(formatter.date(from: stamp) != nil)
            #expect(stamp.hasSuffix("Z"))
            #expect(text.hasSuffix("1970-01-01T00:00:01.000Z [app] App line\n1970-01-01T00:00:02.000Z [tunnel] Extension line\n"))
            #expect(model.logText.isEmpty)
        }

        @Test
        func `export redacts key shaped material from both writers and never logs imported configuration`() async throws {
            let model = model()
            defer { try? FileManager.default.removeItem(at: model.container) }
            let keys = keyShapes()
            let configuration = """
            [Interface]
            PrivateKey = \(keys[0])
            Address = 10.23.45.67/32
            [Peer]
            PublicKey = \(keys[0])
            PresharedKey = \(keys[1])
            AllowedIPs = 0.0.0.0/0
            """
            let runner = Task { await model.run() }
            defer { runner.cancel() }
            try await until { !model.statusHistory.isEmpty }
            model.prepareImport(configuration)
            #expect(model.review != nil)
            await model.confirmImport()
            let profile = try #require(model.profiles.first)
            await model.setTunnel(profile.id, on: true)
            try await until { AppModel.isActive(model.status.phase) }
            await model.setTunnel(profile.id, on: false)
            try await until { model.status.phase == .idle }
            runner.cancel()
            await runner.value
            let extensionLog = SharedLogFile(directory: model.container)
            for key in keys {
                model.log.file.append("PrivateKey = \(key)", process: .app)
                extensionLog.append("Engine error: \(key)", process: .tunnel)
                extensionLog.append("PresharedKey = \(key)", process: .tunnel)
            }
            let exported = model.exportLog()
            expectRedacted(exported, keys: keys)
            let text = String(decoding: exported, as: UTF8.self)
            #expect(text.contains("<secret:"))
            #expect(text.contains("[app] Tunnel active"))
            #expect(text.contains("[app] Tunnel idle"))
            #expect(!text.contains("[Interface]"))
            #expect(!text.contains("[Peer]"))
            #expect(!text.contains("AllowedIPs"))
            #expect(!text.contains(configuration))
        }

        @Test
        func `negative control fails the export leak check when scrubbing is bypassed`() throws {
            let model = model()
            defer { try? FileManager.default.removeItem(at: model.container) }
            let keys = keyShapes()
            // Deliberately bypass SharedLogFile.append's scrubbing, without any product redaction-disable switch.
            let raw = "1000\tapp\tPrivateKey = \(keys[0])\n2000\ttunnel\tPresharedKey = \(keys[1])\n"
            try Data(raw.utf8).write(to: model.log.file.url)
            let exported = model.exportLog()
            withKnownIssue("Negative control: scrubbing bypassed") {
                expectRedacted(exported, keys: keys)
            }
        }

        @Test
        func `an unavailable log stays readable and follows new lines after storage recovers`() async throws {
            let root = FileManager.default.temporaryDirectory.appending(path: "ios-log-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let container = root.appending(path: "blocked")
            try Data().write(to: container)
            let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true, container: container)
            model.log.refreshInterval = .milliseconds(10)
            #expect(model.log.file.read().isEmpty)
            #expect(!model.log.file.append("Unavailable", process: .app))
            #expect(String(decoding: model.exportLog(), as: UTF8.self).hasPrefix("# WGEX shared log exported "))
            let watcher = Task { await model.watchLog() }
            defer { watcher.cancel() }
            try FileManager.default.removeItem(at: container)
            try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
            #expect(model.log.file.append("Recovered", process: .tunnel))
            try await until { model.logText.contains("Recovered") }
            watcher.cancel()
            await watcher.value
        }

        private func keyShapes() -> [String] {
            let bytes = Data((0 ..< 32).map { UInt8(($0 * 17 + 29) % 256) })
            let other = Data(bytes.reversed())
            let base64 = bytes.base64EncodedString()
            return [
                base64, other.base64EncodedString(),
                base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"),
                bytes.map { String(format: "%02x", $0) }.joined(),
            ]
        }

        private func expectRedacted(_ exported: Data, keys: [String], sourceLocation: SourceLocation = #_sourceLocation) {
            let text = String(decoding: exported, as: UTF8.self)
            let safe = keys.allSatisfy { !text.contains($0) && !text.contains(String($0.prefix(16))) }
            #expect(safe, "FAIL: exported text contains private material", sourceLocation: sourceLocation)
        }

        private func until(_ condition: () -> Bool) async throws {
            for _ in 0 ..< 500 {
                if condition() {
                    return
                }
                try await Task.sleep(for: .milliseconds(10))
            }
            throw LogTestError.timedOut
        }

        private enum LogTestError: Error { case timedOut }
    }
#endif
