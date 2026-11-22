// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Bounded DNS wire codec used only with explicitly supplied interface-bound resolvers.
package enum UnderlayDNSCodec {
    package struct Answer {
        package let addresses: [String]
        package let ttl: UInt32
        package let truncated: Bool
    }

    package static func query(host: String, type: UInt16, id: UInt16) throws -> [UInt8] {
        let labels = (host.hasSuffix(".") ? String(host.dropLast()) : host).lowercased().split(
            separator: ".",
            omittingEmptySubsequences: false,
        )
        guard host.utf8.count <= 253, [1, 28].contains(type), !labels.isEmpty,
              labels.allSatisfy({ (1 ... 63).contains($0.utf8.count) && $0.utf8.allSatisfy {
                  (97 ... 122).contains($0) || (48 ... 57).contains($0) || $0 == 45
              } }) else { throw DaemonFailure.hostSystem(EINVAL) }
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in labels {
            bytes.append(UInt8(label.utf8.count)); bytes += label.utf8
        }
        return bytes + [0, UInt8(type >> 8), UInt8(type & 255), 0, 1]
    }

    package static func answer(_ bytes: [UInt8], query: [UInt8]) throws -> Answer {
        guard bytes.count >= query.count, query.count >= 17, bytes.count <= 65535,
              bytes[0 ..< 2] == query[0 ..< 2], bytes[2] & 0xF8 == 0x80, bytes[3] & 0x0F == 0,
              bytes[4] == 0, bytes[5] == 1, bytes[12 ..< query.count] == query[12 ..< query.count]
        else {
            throw DaemonFailure.hostSystem(EBADMSG)
        }
        if bytes[2] & 2 != 0 {
            return Answer(addresses: [], ttl: 0, truncated: true)
        }
        var questionCursor = 12
        let question = try name(query, cursor: &questionCursor)
        let records = try readRecords(bytes, offset: query.count)
        let (allowed, aliasTTL) = allowedNames(records, question: question)
        let requested = UInt16(query[query.count - 4]) << 8 | UInt16(query[query.count - 3])
        var addresses: [String] = []; var ttl = aliasTTL
        for record in records where allowed.contains(record.owner) && record.type == requested {
            try addresses.append(literal(record))
            ttl = min(ttl, record.ttl)
        }
        return Answer(addresses: addresses, ttl: addresses.isEmpty ? 0 : ttl, truncated: false)
    }

    private struct Record {
        let owner: String
        let type: UInt16
        let bytes: [UInt8]
        let ttl: UInt32
        let alias: String?
    }

    private static func allowedNames(_ records: [Record], question: String) -> (Set<String>, UInt32) {
        var allowed = Set([question]); var ttl = UInt32.max
        for _ in 0 ..< 16 {
            for record in records where allowed.contains(record.owner) {
                if let alias = record.alias {
                    allowed.insert(alias); ttl = min(ttl, record.ttl)
                }
            }
        }
        return (allowed, ttl)
    }

    private static func readRecords(_ bytes: [UInt8], offset: Int) throws -> [Record] {
        let count = Int(bytes[6]) << 8 | Int(bytes[7])
        guard count <= 256 else { throw DaemonFailure.hostSystem(EMSGSIZE) }
        var cursor = offset; var records: [Record] = []
        for _ in 0 ..< count {
            try records.append(readRecord(bytes, cursor: &cursor))
        }
        return records
    }

    private static func readRecord(_ bytes: [UInt8], cursor: inout Int) throws -> Record {
        let owner = try name(bytes, cursor: &cursor)
        guard cursor + 10 <= bytes.count else { throw DaemonFailure.hostSystem(EBADMSG) }
        let type = UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1])
        let dnsClass = UInt16(bytes[cursor + 2]) << 8 | UInt16(bytes[cursor + 3])
        let ttl = bytes[cursor + 4 ..< cursor + 8].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let length = Int(bytes[cursor + 8]) << 8 | Int(bytes[cursor + 9]); cursor += 10
        guard cursor + length <= bytes.count else { throw DaemonFailure.hostSystem(EBADMSG) }
        defer { cursor += length }
        var alias: String?
        if type == 5, dnsClass == 1 {
            var aliasCursor = cursor
            alias = try name(bytes, cursor: &aliasCursor)
            guard aliasCursor == cursor + length else { throw DaemonFailure.hostSystem(EBADMSG) }
        }
        return Record(
            owner: owner,
            type: dnsClass == 1 ? type : 0,
            bytes: Array(bytes[cursor ..< cursor + length]),
            ttl: ttl,
            alias: alias,
        )
    }

    private static func literal(_ record: Record) throws -> String {
        guard record.bytes.count == (record.type == 1 ? 4 : 16) else { throw DaemonFailure.hostSystem(EBADMSG) }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let valid = record.bytes.withUnsafeBytes { inet_ntop(
            record.type == 1 ? AF_INET : AF_INET6,
            $0.baseAddress,
            &output,
            socklen_t(output.count),
        ) != nil }
        guard valid else { throw DaemonFailure.hostSystem(EBADMSG) }
        return String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func name(_ bytes: [UInt8], cursor: inout Int) throws -> String {
        var position = cursor; var resumed = false; var labels: [String] = []; var visited: Set<Int> = []
        while true {
            guard position < bytes.count, visited.count < 128,
                  visited.insert(position).inserted else { throw DaemonFailure.hostSystem(EBADMSG) }
            let size = Int(bytes[position]); position += 1
            if size == 0 {
                if !resumed {
                    cursor = position
                }; return labels.joined(separator: ".").lowercased()
            }
            if size & 0xC0 == 0xC0 {
                guard position < bytes.count else { throw DaemonFailure.hostSystem(EBADMSG) }
                if !resumed {
                    cursor = position + 1; resumed = true
                }
                position = (size & 0x3F) << 8 | Int(bytes[position]); continue
            }
            guard size <= 63, position + size <= bytes.count, labels.count < 127 else { throw DaemonFailure.hostSystem(EBADMSG) }
            let label = bytes[position ..< position + size]
            guard label.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }) else { throw DaemonFailure.hostSystem(EBADMSG) }
            labels.append(String(decoding: label, as: UTF8.self)); position += size
            if !resumed {
                cursor = position
            }
        }
    }
}
