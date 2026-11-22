// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import WGEXCore
import WGEXDaemonProtocol

package struct JournalState: Sendable {
    package var document: DaemonJournalDocument
    package var sequence: UInt64
    package var logBytes: Int
    package var failed = false
}

/// Extra checkpoint metadata is ignored by legacy document decoders; the public fields stay at the root.
package struct JournalCheckpoint: Codable {
    package let document: DaemonJournalDocument
    package let sequence: UInt64
    private enum CodingKeys: String, CodingKey { case journalSequence }
    package init(document: DaemonJournalDocument, sequence: UInt64) {
        self.document = document; self.sequence = sequence
    }

    package init(from decoder: any Decoder) throws {
        document = try DaemonJournalDocument(from: decoder)
        sequence = try decoder.container(keyedBy: CodingKeys.self).decodeIfPresent(UInt64.self, forKey: .journalSequence) ?? 0
    }

    package func encode(to encoder: any Encoder) throws {
        try document.encode(to: encoder)
        var metadata = encoder.container(keyedBy: CodingKeys.self)
        try metadata.encode(sequence, forKey: .journalSequence)
    }
}

/// Length, JSON delta, SHA-256. A complete checksum is the transaction commit marker.
package enum JournalRecord {
    private struct Header: Decodable {
        let sequence: UInt64
        let entries: [DaemonJournalEntry]?
        let replaceEntries: Bool?
        let removed: [String]?
        let durable: Bool?
    }

    package static func encode(
        previous: DaemonJournalDocument,
        value: DaemonJournalDocument,
        sequence: UInt64,
        durable: Bool,
    ) throws -> Data {
        var record: [String: Any] = ["sequence": sequence, "durable": durable]
        if value.entries != previous.entries {
            let append = value.entries.starts(with: previous.entries)
            let entries = append ? Array(value.entries.dropFirst(previous.entries.count)) : value.entries
            record["entries"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(entries))
            record["replaceEntries"] = !append
        }
        var old = previous, next = value
        old.entries = []; next.entries = []
        if old.resources != next.resources {
            record["resources"] = try resourceEdits(previous: old.resources, value: next.resources)
        }
        old.resources = []; next.resources = []
        if old != next {
            let before = try fields(old), after = try fields(next)
            record["set"] = after.filter { key, value in (before[key] as? NSObject)?.isEqual(value) != true }
            record["removed"] = before.keys.filter { after[$0] == nil }
        }
        let body = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
        guard body.count <= 8 * 1024 * 1024 - 36 else { throw DaemonFailure.stateTooLarge }
        // The high bit identifies a discardable bookkeeping tail even if its JSON was torn/corrupted.
        let length = body.count | (durable ? 0 : 0x8000_0000)
        var frame = Data((0 ..< 4).map { UInt8(truncatingIfNeeded: length >> ($0 * 8)) })
        frame.append(body); frame.append(contentsOf: SHA256.hash(data: body))
        return frame
    }

    package static func replay(_ data: Data, checkpoint: JournalCheckpoint) throws -> JournalState {
        var state = JournalState(document: checkpoint.document, sequence: checkpoint.sequence, logBytes: 0)
        let bytes = Array(data)
        var offset = 0
        var lastSequence: UInt64 = 0
        while offset + 4 <= bytes.count {
            let length = (0 ..< 4).reduce(0) { $0 | Int(bytes[offset + $1]) << ($1 * 8) }
            let size = length & 0x7FFF_FFFF, bookkeeping = length & 0x8000_0000 != 0
            if size == 0, bytes[offset...].allSatisfy({ $0 == 0 }) {
                break
            }
            guard size > 0, size <= 8 * 1024 * 1024 - 36 else { throw DaemonFailure.stateInvalidDocument }
            guard offset + size + 36 <= bytes.count else { break }
            let body = Data(bytes[(offset + 4) ..< (offset + size + 4)])
            let digest = bytes[(offset + size + 4) ..< (offset + size + 36)]
            if Array(SHA256.hash(data: body)) != Array(digest) {
                if offset + size + 36 == bytes.count, bookkeeping {
                    break
                }
                throw DaemonFailure.stateInvalidDocument
            }
            let header = try JSONDecoder().decode(Header.self, from: body)
            guard !bookkeeping || header.durable != true, header.sequence > lastSequence else { throw DaemonFailure.stateInvalidDocument }
            lastSequence = header.sequence
            if header.sequence > state.sequence {
                guard state.sequence < UInt64.max, header.sequence == state.sequence + 1 else { throw DaemonFailure.stateInvalidDocument }
                state.document = try apply(body, header: header, to: state.document)
                state.sequence = header.sequence
            }
            offset += size + 36
        }
        state.logBytes = offset
        return state
    }

    private static func apply(_ body: Data, header: Header, to document: DaemonJournalDocument) throws -> DaemonJournalDocument {
        var next = document
        guard let record = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw DaemonFailure.stateInvalidDocument }
        let changed = record["set"] as? [String: Any] ?? [:]
        if !changed.isEmpty || !(header.removed ?? []).isEmpty {
            var values = try fields(next)
            for key in header.removed ?? [] {
                values.removeValue(forKey: key)
            }
            values.merge(changed) { _, new in new }
            next = try JSONDecoder().decode(DaemonJournalDocument.self, from: JSONSerialization.data(withJSONObject: values))
        }
        next.entries = (header.replaceEntries == true ? [] : document.entries) + (header.entries ?? [])
        if let edits = record["resources"] as? [[String: Any]] {
            next.resources = try restoreResources(edits, previous: next.resources)
        }
        return DaemonJournal.compact(next)
    }

    private static func resourceEdits(previous: [GenerationResources], value: [GenerationResources]) throws -> [[String: Any]] {
        try value.map { resource in
            let existing = previous.first { $0.generation == resource.generation }
            var old = existing ?? GenerationResources(generation: resource.generation), next = resource
            // Unchanged large lists never enter the encoder for a metadata-only step.
            if existing != nil, old.routes == next.routes {
                old.routes = []; next.routes = []
            }
            if existing != nil, old.addresses == next.addresses {
                old.addresses = []; next.addresses = []
            }
            let before = try existing == nil ? [:] : fields(old), after = try fields(next)
            return [
                "generation": resource.generation.rawValue,
                "set": after.filter { key, value in (before[key] as? NSObject)?.isEqual(value) != true },
                "removed": before.keys.filter { after[$0] == nil },
            ]
        }
    }

    private static func restoreResources(_ edits: [[String: Any]], previous: [GenerationResources]) throws -> [GenerationResources] {
        try edits.map { edit in
            let generation = try JSONDecoder().decode(Generation.self, from: JSONSerialization.data(
                withJSONObject: edit["generation"] ?? NSNull(), options: [.fragmentsAllowed],
            ))
            var values = try fields(previous.first { $0.generation == generation } ?? GenerationResources(generation: generation))
            for key in edit["removed"] as? [String] ?? [] {
                values.removeValue(forKey: key)
            }
            guard let changed = edit["set"] as? [String: Any] else { throw DaemonFailure.stateInvalidDocument }
            values.merge(changed) { _, new in new }
            return try JSONDecoder().decode(GenerationResources.self, from: JSONSerialization.data(withJSONObject: values))
        }
    }

    private static func fields(_ value: some Encodable) throws -> [String: Any] {
        guard let fields = try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any] else {
            throw DaemonFailure.stateInvalidDocument
        }
        return fields
    }
}
