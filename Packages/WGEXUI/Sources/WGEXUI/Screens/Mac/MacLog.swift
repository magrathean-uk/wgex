// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Observation
    import WGEXCore

    /// One tunnel or daemon log line as the daemon's `logs` reply carries it, already redacted there.
    public nonisolated struct MacLogLine: Sendable, Hashable {
        public var date: Date
        public var category: String
        public var message: String

        public init(date: Date, category: String, message: String) {
            self.date = date
            self.category = category
            self.message = message
        }
    }

    /// Second, local redaction pass: whatever a source returns, key-shaped text and key assignments never reach the view,
    /// the saved file or a log line.
    public nonisolated enum MacLogRedaction {
        /// Replaces key material.
        public static let replacement = "<key>"

        /// Replaces base64, base64url and hex key shapes (fragments included) and `PrivateKey`/`PresharedKey` values.
        public static func scrub(_ text: String) -> String {
            var bytes = Array(text.utf8)
            let matches = bytes.withUnsafeBytes { KeyShape.matches(in: $0, includeFragments: true) }
            for match in matches.reversed() {
                bytes.replaceSubrange(match.range, with: Array(replacement.utf8))
            }
            let scrubbed = String(decoding: bytes, as: UTF8.self)
            let assignment = /\b(PrivateKey|PresharedKey)\s*=\s*\S+/.ignoresCase()
            return scrubbed.replacing(assignment) { match in "\(match.output.1) = \(replacement)" }
        }
    }

    /// The bounded log the activity view holds: at most `capacity` lines of at most `messageLimit` characters, oldest
    /// dropped first. Every line is scrubbed on entry, so nothing unredacted is ever stored.
    public nonisolated struct MacLogBuffer: Sendable, Equatable {
        /// A stored line with a stable identity for the list.
        public struct Entry: Sendable, Hashable, Identifiable {
            public let id: UInt64
            public let line: MacLogLine
        }

        public static let capacity = 2000
        public static let messageLimit = 1024
        private static let categoryLimit = 32

        public private(set) var entries: [Entry] = []
        private var nextID: UInt64 = 0
        /// Lines already held at the newest date; a read from that date returns them again.
        private var boundary: Set<MacLogLine> = []

        public init() {}

        public var lines: [MacLogLine] {
            entries.map(\.line)
        }

        /// The date the next read starts from.
        public var cursor: Date? {
            entries.last?.line.date
        }

        /// Appends lines newer than the held ones, skipping repeats at the newest date. Returns whether anything changed.
        @discardableResult
        public mutating func merge(_ incoming: [MacLogLine]) -> Bool {
            var changed = false
            for raw in incoming.sorted(by: { $0.date < $1.date }) {
                let line = MacLogLine(
                    date: raw.date,
                    // Scrub before cutting, so a cut can never leave a key fragment too short to recognise.
                    category: String(MacLogRedaction.scrub(raw.category).prefix(Self.categoryLimit)),
                    message: String(MacLogRedaction.scrub(raw.message).prefix(Self.messageLimit)),
                )
                if let cursor {
                    if line.date < cursor || (line.date == cursor && boundary.contains(line)) {
                        continue
                    }
                    if line.date > cursor {
                        boundary = []
                    }
                }
                boundary.insert(line)
                entries.append(Entry(id: nextID, line: line))
                nextID &+= 1
                changed = true
            }
            if entries.count > Self.capacity {
                entries.removeFirst(entries.count - Self.capacity)
            }
            return changed
        }

        /// One line as shown and saved: UTC timestamp, category, message.
        public static func render(_ line: MacLogLine) -> String {
            "\(line.date.formatted(timestamp)) [\(line.category)] \(line.message)"
        }

        private static let timestamp = Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt)

        /// The whole log as the saved text, one line each.
        public var text: String {
            entries.map { Self.render($0.line) + "\n" }.joined()
        }
    }

    /// The activity view's log: read from the daemon while the view shows it, held bounded and scrubbed, saved on request.
    @MainActor @Observable
    public final class MacActivityLog {
        public private(set) var buffer = MacLogBuffer()
        /// False after a read failed; the view then says the log is unavailable.
        public private(set) var available = true
        @ObservationIgnored private var readInFlight = false
        @ObservationIgnored private let read: (Date?) async throws -> [MacLogLine]

        /// `read` is the app's `MacShellOperations.readLog`.
        public init(read: @escaping (Date?) async throws -> [MacLogLine]) {
            self.read = read
        }

        /// One read from the held cursor. Overlapping calls are dropped; a failure keeps the held lines.
        public func refresh() async {
            guard !readInFlight else { return }
            readInFlight = true
            defer { readInFlight = false }
            do {
                let lines = try await read(buffer.cursor)
                buffer.merge(lines)
                available = true
            } catch {
                available = false
            }
        }

        /// Writes the held log to the URL the user chose; nothing is written anywhere else.
        public func save(to url: URL) throws {
            try MacLogFile.write(buffer.text, to: url)
        }
    }

    /// Saving the log: only to the URL the user chose, with an atomic replace.
    public nonisolated enum MacLogFile {
        public static func write(_ text: String, to url: URL) throws {
            try Data(text.utf8).write(to: url, options: .atomic)
        }

        /// Default name in the save panel.
        public static func suggestedName(at date: Date) -> String {
            let stamp = date.formatted(Date.ISO8601FormatStyle(timeZone: .gmt).year().month().day().dateSeparator(.dash)
                .time(includingFractionalSeconds: false).timeSeparator(.omitted))
            return MacStrings.logFilename(stamp)
        }
    }
#endif
