// SPDX-License-Identifier: MIT

#if os(macOS)
    import Darwin
    import Foundation
    import Testing
    import WGEXUI

    /// The export sequence through its production entry point with a stub daemon and a stub save destination.
    @MainActor
    private struct MacDiagnosticsExportTests {
        private struct DaemonDown: Error {}
        private final class Recorder {
            var fetches: [Bool] = []
            var panelNames: [String] = []
        }

        private static let archive = Data((0 ..< 4096).map { UInt8(truncatingIfNeeded: $0 &* 7) })

        private static func folder() throws -> URL {
            let url = URL(filePath: NSTemporaryDirectory()).appending(path: "wgex-diag-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            return url
        }

        private static func contents(_ folder: URL) throws -> [String] {
            try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()
        }

        private func make(
            _ record: Recorder, reply: Result<Data, any Error> = .success(MacDiagnosticsExportTests.archive), destination: URL?,
            write: @escaping @Sendable (Data, URL) throws -> Void = MacDiagnosticsFile.write,
        ) -> MacDiagnosticsExport {
            MacDiagnosticsExport(
                fetch: { includeLogs in record.fetches.append(includeLogs); return try reply.get() },
                chooseDestination: { name in record.panelNames.append(name); return destination },
                write: write,
                errorCopy: { _ in "daemon-copy" },
            )
        }

        @Test func `success writes the daemon bytes unchanged with mode 0600 and a UTC stamped default name`() async throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let record = Recorder()
            let target = folder.appending(path: "out.zip")
            let export = make(record, destination: target)
            export.includeLogs = false
            await export.export(at: Date(timeIntervalSince1970: 1_700_000_000))
            #expect(export.phase == .saved)
            #expect(record.fetches == [false])
            #expect(record.panelNames == ["WGEX Diagnostics 2023-11-14T221320Z.zip"])
            #expect(try Data(contentsOf: target) == Self.archive)
            var info = stat()
            #expect(stat(target.path, &info) == 0)
            #expect(info.st_mode & 0o777 == 0o600)
            #expect(try Self.contents(folder) == ["out.zip"])
        }

        @Test func `include logs is passed to the daemon and defaults on`() async {
            let record = Recorder()
            let export = make(record, destination: nil)
            #expect(export.includeLogs)
            await export.export()
            #expect(record.fetches == [true])
        }

        @Test func `cancelling the save panel writes nothing`() async throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let record = Recorder()
            let export = make(record, destination: nil)
            await export.export()
            #expect(export.phase == .cancelled)
            #expect(try Self.contents(folder).isEmpty)
        }

        @Test func `a daemon error shows in the sheet and never opens the save panel`() async {
            let record = Recorder()
            let export = make(record, reply: .failure(DaemonDown()), destination: URL(filePath: "/nonexistent/never.zip"))
            await export.export()
            #expect(export.phase == .failed("daemon-copy"))
            #expect(record.panelNames.isEmpty)
        }

        @Test func `a failed write reports the error and leaves no partial file`() async throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let record = Recorder()
            // Unwritable destination: the folder does not exist, so creation fails before any byte lands.
            let missing = folder.appending(path: "absent/out.zip")
            let export = make(record, destination: missing)
            await export.export()
            #expect(export.phase == .failed(MacStrings.theDiagnosticsCouldNotBeSaved))
            #expect(try Self.contents(folder).isEmpty)
            // A read-only folder refuses the temporary file too.
            let locked = folder.appending(path: "locked")
            try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: locked.path)
            defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: locked.path) }
            let again = make(record, destination: locked.appending(path: "out.zip"))
            await again.export()
            #expect(again.phase == .failed(MacStrings.theDiagnosticsCouldNotBeSaved))
            #expect(try Self.contents(locked).isEmpty)
        }

        @Test func `a write that fails after the temporary file exists removes it and keeps an existing destination`() throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            // The destination is a non-empty directory: rename over it fails after the bytes were written.
            let target = folder.appending(path: "out.zip")
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
            try Data("x".utf8).write(to: target.appending(path: "keep"))
            #expect(throws: MacDiagnosticsFile.WriteFailure.self) { try MacDiagnosticsFile.write(Self.archive, to: target) }
            #expect(try Self.contents(folder) == ["out.zip"])
            #expect(try Self.contents(target) == ["keep"])
        }

        @Test func `a second export while one runs is ignored and the sheet can be reset`() async {
            let gate = Gate()
            let record = Recorder()
            let export = MacDiagnosticsExport(
                fetch: { includeLogs in record.fetches.append(includeLogs); await gate.wait(); return Self.archive },
                chooseDestination: { _ in nil },
            )
            let first = Task { await export.export() }
            while record.fetches.isEmpty {
                await Task.yield()
            }
            #expect(export.isWorking)
            await export.export()
            #expect(record.fetches.count == 1)
            export.reset()
            #expect(export.isWorking)
            await gate.open()
            await first.value
            #expect(export.phase == .cancelled)
            export.reset()
            #expect(export.phase == .idle)
        }

        /// The production wiring the sheet uses: the shell's operations, its error copy, the real file writer.
        private func shell(_ record: Recorder, reply: Result<Data, any Error>) -> MacShellOperations {
            MacShellOperations(
                errorCopy: { _ in MacErrorCopy(.unknown) },
                exportDiagnostics: { includeLogs in record.fetches.append(includeLogs); return try reply.get() },
            )
        }

        @Test func `the production wiring saves the stub client archive`() async throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let record = Recorder()
            let target = folder.appending(path: "out.zip")
            let export = MacDiagnosticsExport(operations: shell(record, reply: .success(Self.archive))) { name in
                record.panelNames.append(name); return target
            }
            await export.export()
            #expect(export.phase == .saved)
            #expect(record.fetches == [true])
            #expect(try Data(contentsOf: target) == Self.archive)
        }

        @Test func `the production wiring cancels, refuses and fails writes without a file`() async throws {
            let folder = try Self.folder()
            defer { try? FileManager.default.removeItem(at: folder) }
            let record = Recorder()
            let cancelled = MacDiagnosticsExport(operations: shell(record, reply: .success(Self.archive))) { _ in nil }
            await cancelled.export()
            #expect(cancelled.phase == .cancelled)
            let refused = MacDiagnosticsExport(operations: shell(record, reply: .failure(DaemonDown()))) { _ in
                record.panelNames.append("never"); return folder.appending(path: "never.zip")
            }
            await refused.export()
            #expect(refused.phase == .failed(MacErrorCopy(.unknown).message))
            #expect(record.panelNames.isEmpty)
            let broken = MacDiagnosticsExport(operations: shell(record, reply: .success(Self.archive))) { _ in
                folder.appending(path: "absent/out.zip")
            }
            await broken.export()
            #expect(broken.phase == .failed(MacStrings.theDiagnosticsCouldNotBeSaved))
            #expect(try Self.contents(folder).isEmpty)
        }

        @Test func `the strings the sheet shows are in the catalogue`() {
            #expect(MacStrings.diagnosticsContents.count == 4)
        }
    }

    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var isOpen = false
        func wait() async {
            if isOpen {
                return
            }
            await withCheckedContinuation { continuation = $0 }
        }

        func open() {
            isOpen = true
            continuation?.resume()
            continuation = nil
        }
    }
#endif
