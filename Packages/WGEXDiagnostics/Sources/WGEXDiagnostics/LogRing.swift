// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// Per-process bounded storage. Raw messages are accessible only to the redactor.
/// A chunk carries a one-byte continuation marker and at most 511 UTF-8 bytes.
/// Overflow evicts entire messages; a truncated secret is never exposed as a new line.
public final class LogRing: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let capacity = 4096
    public static let entryByteCount = 512
    public static let process = LogRing()

    public struct RedactedLine: Codable, Sendable, Hashable {
        public let date: Date
        public let category: String
        public let message: String
    }

    private struct Chunk: Sendable {
        let date: Date
        let category: LogCategory
        let bytes: [UInt8]
    }

    private struct Storage: Sendable {
        var slots: [Chunk?] = Array(repeating: nil, count: LogRing.capacity)
        var head = 0
        var count = 0

        mutating func evictMessage() {
            repeat {
                slots[head] = nil
                head = (head + 1) % LogRing.capacity
                count -= 1
            } while count > 0 && slots[head]?.bytes.first == 1
        }
    }

    private let storage = Mutex(Storage())
    public var description: String {
        "<LogRing>"
    }

    public var debugDescription: String {
        description
    }

    public init() {}

    /// Messages larger than the entire ring are dropped, rather than partially retained.
    /// Callers must never deliberately log keys, raw configurations or raw UAPI.
    public func append(_ message: String, category: LogCategory, date: Date = Date()) {
        let bytes = Array(message.utf8)
        let payload = Self.entryByteCount - 1
        let needed = max(1, (bytes.count + payload - 1) / payload)
        guard needed <= Self.capacity else { return }
        storage.withLock { state in
            while state.count + needed > Self.capacity {
                state.evictMessage()
            }
            for index in 0 ..< needed {
                let lower = index * payload
                let upper = min(bytes.count, lower + payload)
                let chunk = Chunk(date: date, category: category, bytes: [index == 0 ? 0 : 1] + bytes[lower ..< upper])
                state.slots[(state.head + state.count) % Self.capacity] = chunk
                state.count += 1
            }
        }
    }

    public var entryCount: Int {
        storage.withLock { $0.count }
    }

    /// Snapshots atomically, reassembles bytes before UTF-8 decoding, then redacts.
    /// Ownership and per-uid filtering belong to the daemon before export.
    public func redactedLines(using redactor: Redactor) -> [RedactedLine] {
        let chunks = storage.withLock { state in
            (0 ..< state.count).compactMap { state.slots[(state.head + $0) % Self.capacity] }
        }
        var lines: [RedactedLine] = []
        var bytes: [UInt8] = []
        var date = Date(timeIntervalSince1970: 0)
        var category = LogCategory.app
        var hasLine = false
        func flush() {
            lines.append(RedactedLine(
                date: date,
                category: category.rawValue,
                message: redactor.redact(String(decoding: bytes, as: UTF8.self)),
            ))
        }
        for chunk in chunks {
            if chunk.bytes.first == 0 {
                if hasLine {
                    flush()
                }
                bytes = []; date = chunk.date; category = chunk.category; hasLine = true
            }
            bytes.append(contentsOf: chunk.bytes.dropFirst())
        }
        if !chunks.isEmpty {
            flush()
        }
        return lines
    }
}
