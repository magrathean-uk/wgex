// SPDX-License-Identifier: MIT
import Foundation

/// A bounded log file shared by the app and the tunnel extension (the App Group container at run time).
/// Every message is redacted before it is written, so the file never holds raw key material.
/// Writers serialise on a sibling lock file; eviction removes whole lines only.
/// No method throws: a missing, unwritable or corrupt file yields `false` or fewer lines.
public final class SharedLogFile: Sendable {
    public enum Process: String, Sendable, CaseIterable {
        case app, tunnel
    }

    public struct Entry: Sendable, Hashable {
        public let date: Date
        public let process: Process
        public let message: String
    }

    public static let defaultCapBytes = 256 * 1024
    public static let maxLineBytes = 2048

    public let url: URL
    public let capBytes: Int
    private let lockURL: URL
    private let redactor: Redactor

    public init(
        directory: URL,
        name: String = "wgex-shared.log",
        capBytes: Int = SharedLogFile.defaultCapBytes,
        redactor: Redactor = Redactor(),
    ) {
        url = directory.appending(path: name, directoryHint: .notDirectory)
        lockURL = directory.appending(path: name + ".lock", directoryHint: .notDirectory)
        self.capBytes = max(capBytes, Self.maxLineBytes + 64)
        self.redactor = redactor
    }

    /// Redacts, flattens to one line, appends, then evicts the oldest whole lines above the cap.
    @discardableResult
    public func append(_ message: String, process: Process, date: Date = Date()) -> Bool {
        let line = Self.encode(redactor.redact(message), process: process, date: date)
        return withLock {
            let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
            guard fd >= 0 else { return false }
            defer { close(fd) }
            // A crash can leave a torn final line; start on a fresh line so only that fragment is lost.
            var prefix = Data()
            var last: UInt8 = 0x0A
            let probe = open(url.path, O_RDONLY)
            if probe >= 0 {
                if lseek(probe, -1, SEEK_END) >= 0, Darwin.read(probe, &last, 1) == 1, last != 0x0A {
                    prefix = Data([0x0A])
                }
                close(probe)
            }
            guard Self.writeAll(fd, prefix + line) else { return false }
            var info = stat()
            if fstat(fd, &info) == 0, Int(info.st_size) > capBytes {
                evict()
            }
            return true
        } ?? false
    }

    /// Valid lines in time order (ties keep file order). Corrupt lines are skipped.
    public func read() -> [Entry] {
        let data = withLock { (try? Data(contentsOf: url)) ?? Data() } ?? Data()
        return Self.parse(data).enumerated()
            .sorted { ($0.element.date, $0.offset) < ($1.element.date, $1.offset) }
            .map(\.element)
    }

    /// UTF-8 text: a UTC timestamp header, then `timestamp [process] message` per line.
    public func export(now: Date = Date()) -> Data {
        let stamp = Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt)
        var text = "# WGEX shared log exported \(now.formatted(stamp))\n"
        for entry in read() {
            text += "\(entry.date.formatted(stamp)) [\(entry.process.rawValue)] \(entry.message)\n"
        }
        return Data(text.utf8)
    }

    // MARK: - Internals

    private func withLock<T>(_ body: () -> T) -> T? {
        let lock = open(lockURL.path, O_RDWR | O_CREAT, 0o600)
        guard lock >= 0 else { return nil }
        defer { close(lock) }
        while flock(lock, LOCK_EX) != 0 {
            if errno != EINTR {
                return nil
            }
        }
        defer { flock(lock, LOCK_UN) }
        return body()
    }

    /// Caller holds the lock. Rewrites through a temporary file and an atomic rename.
    private func evict() {
        guard let data = try? Data(contentsOf: url) else { return }
        var lines: [Data] = []
        var start = data.startIndex
        while let end = data[start...].firstIndex(of: 0x0A) {
            lines.append(data[start ... end])
            start = end + 1
        }
        // A trailing fragment without a newline is dropped, as is anything oldest above 3/4 of the cap.
        var total = lines.reduce(0) { $0 + $1.count }
        var drop = 0
        while total > capBytes * 3 / 4, drop < lines.count {
            total -= lines[drop].count
            drop += 1
        }
        let kept = lines[drop...].reduce(into: Data()) { $0.append($1) }
        let temp = url.appendingPathExtension("tmp")
        // Created 0600 explicitly: the umask must not decide the log's mode after the rename.
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard fd >= 0 else { return }
        let written = Self.writeAll(fd, kept)
        close(fd)
        if !written || rename(temp.path, url.path) != 0 {
            unlink(temp.path)
        }
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                return true
            }
            var offset = 0
            while offset < raw.count {
                let count = write(fd, base + offset, raw.count - offset)
                if count < 0 {
                    if errno == EINTR {
                        continue
                    }
                    return false
                }
                offset += count
            }
            return true
        }
    }

    /// `millis<TAB>process<TAB>message\n`; newlines and tabs in the message are escaped.
    private static func encode(_ redacted: String, process: Process, date: Date) -> Data {
        var flat = ""
        for scalar in redacted.unicodeScalars {
            switch scalar {
            case "\n": flat += "\\n"
            case "\r": flat += "\\r"
            case "\t": flat += "\\t"
            case "\\": flat += "\\\\"
            default: flat.unicodeScalars.append(scalar)
            }
        }
        // The message is already redacted, so a cut here only drops redacted text. Cut on a scalar boundary.
        var bytes = 0
        var cut = flat.unicodeScalars.startIndex
        for index in flat.unicodeScalars.indices {
            let size = flat.unicodeScalars[index].utf8.count
            if bytes + size > maxLineBytes {
                break
            }
            bytes += size
            cut = flat.unicodeScalars.index(after: index)
        }
        let millis = Int64((date.timeIntervalSince1970 * 1000).rounded())
        return Data("\(millis)\t\(process.rawValue)\t\(String(flat.unicodeScalars[..<cut]))\n".utf8)
    }

    private static func parse(_ data: Data) -> [Entry] {
        String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true).compactMap { line in
            let fields = line.split(separator: "\t", maxSplits: 2, omittingEmptySubsequences: false)
            guard fields.count == 3, let millis = Int64(fields[0]), let process = Process(rawValue: String(fields[1])) else { return nil }
            var message = ""
            var escaped = false
            for character in fields[2] {
                if escaped {
                    switch character {
                    case "n": message += "\n"
                    case "r": message += "\r"
                    case "t": message += "\t"
                    default: message.append(character)
                    }
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else {
                    message.append(character)
                }
            }
            return Entry(date: Date(timeIntervalSince1970: Double(millis) / 1000), process: process, message: message)
        }
    }
}
