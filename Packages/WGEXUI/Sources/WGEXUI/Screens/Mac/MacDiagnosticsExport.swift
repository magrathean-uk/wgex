// SPDX-License-Identifier: MIT

#if os(macOS)
    import Darwin
    import Foundation
    import Observation

    /// Diagnostics export sequence: ask the daemon for its archive, ask for a destination, write the archive unchanged.
    /// Nothing reaches the destination unless the whole archive was written.
    @MainActor @Observable
    public final class MacDiagnosticsExport {
        public enum Phase: Equatable {
            case idle, working, saved, cancelled
            /// The sheet shows this message and stays open.
            case failed(String)
        }

        public var includeLogs = true
        public private(set) var phase = Phase.idle
        @ObservationIgnored private let fetch: (Bool) async throws -> Data
        @ObservationIgnored private let chooseDestination: (String) async -> URL?
        @ObservationIgnored private let write: @Sendable (Data, URL) throws -> Void
        @ObservationIgnored private let copy: (any Error) -> String

        /// `fetch` is `MacShellOperations.exportDiagnostics`; `chooseDestination` shows the save panel for a default name.
        public init(
            fetch: @escaping (Bool) async throws -> Data,
            chooseDestination: @escaping (String) async -> URL?,
            write: @escaping @Sendable (Data, URL) throws -> Void = MacDiagnosticsFile.write,
            errorCopy: @escaping (any Error) -> String = { MacErrorCopy(error: $0).message },
        ) {
            self.fetch = fetch
            self.chooseDestination = chooseDestination
            self.write = write
            copy = errorCopy
        }

        /// The production wiring: the shell's daemon operation and its error copy.
        public convenience init(
            operations: MacShellOperations,
            chooseDestination: @escaping (String) async -> URL?,
            write: @escaping @Sendable (Data, URL) throws -> Void = MacDiagnosticsFile.write,
        ) {
            self.init(
                fetch: { try await operations.exportDiagnostics($0) },
                chooseDestination: chooseDestination,
                write: write,
                errorCopy: { operations.errorCopy($0).message },
            )
        }

        public var isWorking: Bool {
            phase == .working
        }

        /// The one entry point the sheet calls. A second call while one runs is ignored.
        public func export(at date: Date = Date()) async {
            guard !isWorking else { return }
            phase = .working
            let archive: Data
            do { archive = try await fetch(includeLogs) } catch {
                phase = .failed(copy(error)); return
            }
            guard let url = await chooseDestination(MacDiagnosticsFile.suggestedName(at: date)) else {
                phase = .cancelled; return
            }
            // File I/O (including fsync) runs off the main actor so the window stays responsive.
            let write = write
            do { try await Task.detached { try write(archive, url) }.value; phase = .saved } catch {
                phase = .failed(MacStrings.theDiagnosticsCouldNotBeSaved)
            }
        }

        public func reset() {
            if !isWorking {
                phase = .idle
            }
        }
    }

    /// Writing the archive: 0600 from creation in the destination folder, then an atomic replace; a failure unlinks the
    /// temporary file, so no partial file remains.
    public nonisolated enum MacDiagnosticsFile {
        public struct WriteFailure: Error {}

        public static func write(_ data: Data, to url: URL) throws {
            guard url.isFileURL else { throw WriteFailure() }
            let temporary = url.deletingLastPathComponent().appendingPathComponent(".wgex-\(UUID().uuidString)")
            let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard descriptor >= 0 else { throw WriteFailure() }
            var renamed = false
            defer {
                close(descriptor); if !renamed {
                    unlink(temporary.path)
                }
            }
            guard fchmod(descriptor, mode_t(0o600)) == 0 else { throw WriteFailure() }
            try data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let count = Darwin.write(descriptor, raw.baseAddress?.advanced(by: offset), raw.count - offset)
                    if count < 0, errno == EINTR {
                        continue
                    }
                    guard count > 0 else { throw WriteFailure() }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0, rename(temporary.path, url.path) == 0 else { throw WriteFailure() }
            renamed = true
        }

        /// Default save-panel name with a UTC stamp.
        public static func suggestedName(at date: Date) -> String {
            let stamp = date.formatted(Date.ISO8601FormatStyle(timeZone: .gmt).year().month().day().dateSeparator(.dash)
                .time(includingFractionalSeconds: false).timeSeparator(.omitted))
            return MacStrings.diagnosticsFilename(stamp)
        }
    }
#endif
