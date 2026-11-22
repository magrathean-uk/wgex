// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Conservative parsing: unknown tokens, rules, changed ordering and missing counters fail closed.
public enum PacketFilterReadback {
    public static func matches(_ actual: String, rendered: String) -> Bool {
        canonical(actual) == canonical(rendered)
    }

    package static func canonical(_ text: String) -> [String] {
        text.split(separator: "\n").compactMap { line -> String? in
            var value = line.trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("table <wgex_"), value.contains("> const { "), value.hasSuffix(" }") {
                return nil
            }
            if value.hasSuffix("]"), value.hasPrefix("[ Evaluations:") || value.hasPrefix("[ Inserted:") {
                return nil
            }
            if value.hasPrefix("@"), let space = value.firstIndex(of: " ") {
                value = String(value[value.index(after: space)...])
            }
            value = value.replacingOccurrences(of: "from any to any", with: "all")
            value = value.replacingOccurrences(of: "port = ", with: "port ")
            value = value.replacingOccurrences(of: "user = ", with: "user ")
                .replacingOccurrences(of: "group = ", with: "group ")
            value = value.replacingOccurrences(of: "user root", with: "user 0")
            value = value.replacingOccurrences(of: "proto ipv6-icmp", with: "proto icmp6")
            // PF prints host masks without /32 or /128; neither changes the host selector.
            value = value.split(whereSeparator: \.isWhitespace).map { token in
                let token = Self.canonicalCIDR(String(token))
                if token.contains(":"), token.hasSuffix("/128") {
                    return String(token.dropLast(4))
                }
                if token.contains("."), !token.contains(":"), token.hasSuffix("/32") {
                    return String(token.dropLast(3))
                }
                return String(token)
            }.joined(separator: " ")
            for (name, number) in [
                ("routersol", "133"),
                ("routeradv", "134"),
                ("neighbrsol", "135"),
                ("neighbradv", "136"),
                ("toobig", "2"),
                ("unreach", "3"),
            ] {
                value = value.replacingOccurrences(of: "icmp6-type \(name)", with: "icmp6-type \(number)")
                value = value.replacingOccurrences(of: "icmp-type \(name)", with: "icmp-type \(number)")
            }
            value = value.replacingOccurrences(of: "code needfrag", with: "code 4")
            return value.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        }.filter { !$0.isEmpty }
    }

    private static func canonicalCIDR(_ token: String) -> String {
        guard token.contains("/"), let range = try? IPAddressRange(token) else { return token }
        return range.network.stringRepresentation
    }

    public static func token(_ output: String) throws -> String {
        // `pfctl -E` prints "Token: N" up to macOS 15 and "Token : N" on macOS 26 (lab guest, 26 Oct 2026).
        let tokens = output.split(separator: "\n").compactMap { line -> String? in
            let words = line.replacingOccurrences(of: ":", with: " : ").split(whereSeparator: \.isWhitespace)
            guard words.count == 3, words[0] == "Token", words[1] == ":", validToken(String(words[2])) else { return nil }
            return String(words[2])
        }
        guard tokens.count == 1, let token = tokens.first else { throw DaemonFailure.pfToken }
        return token
    }

    public static func validToken(_ token: String) -> Bool {
        !token.isEmpty && token.utf8.allSatisfy { (48 ... 57).contains($0) } && UInt64(token) != nil
    }

    /// A macOS reference row. Ownership compensation requires both PID and process name.
    public struct Reference: Sendable, Equatable {
        /// Child PID recorded by the kernel.
        public let pid: Int32
        /// Kernel process name; only pfctl is eligible for attempt compensation.
        public let process: String
        /// Numeric enable reference.
        public let token: String
        /// Reference age in seconds when the kernel prints an elapsed timestamp.
        public let age: TimeInterval?
        /// Absolute timestamp when the kernel prints epoch time instead.
        public let createdAt: Date?

        /// A rounded elapsed timestamp must describe a reference acquired after the write-ahead attempt.
        public func matchesAttempt(at: Date, now: Date, maximumDelay: TimeInterval = 10) -> Bool {
            guard let created = createdAt ?? age.map({ now.addingTimeInterval(-$0) }) else { return false }
            return maximumDelay > 0 && maximumDelay.isFinite && at <= now.addingTimeInterval(2)
                && created >= at.addingTimeInterval(-2) && created <= at.addingTimeInterval(maximumDelay + 2)
                && created <= now.addingTimeInterval(2)
        }
    }

    /// Parses recognised rows from the right; unrelated warnings and unknown layouts never abort recovery.
    public static func references(_ text: String) throws -> [Reference] {
        text.split(separator: "\n").compactMap { line in
            let words = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard words.count >= 4, let pid = Int32(words[0]), pid > 0 else { return nil }
            for index in stride(from: words.count - 2, through: 2, by: -1) where validToken(words[index]) {
                guard let stamp = referenceTimestamp(Array(words[(index + 1)...])) else { continue }
                return Reference(
                    pid: pid,
                    process: words[1 ..< index].joined(separator: " "),
                    token: words[index],
                    age: stamp.age,
                    createdAt: stamp.date,
                )
            }
            return nil
        }
    }

    private static func referenceTimestamp(_ words: [String]) -> (age: TimeInterval?, date: Date?)? {
        if words.count == 3, ["day", "days"].contains(words[1]), let days = Double(words[0]),
           let time = elapsedTime(words[2])
        {
            return (days * 86400 + time, nil)
        }
        if words.count == 1 {
            if let time = elapsedTime(words[0]) {
                return (time, nil)
            }
            if let age = Double(words[0]), age.isFinite, age >= 0 {
                return (age, nil)
            }
            if let date = ISO8601DateFormatter().date(from: words[0]) {
                return (nil, date)
            }
            // Unknown single-column timestamps still permit PID/name/token ownership checks,
            // but never authorise attempt compensation without a measurable age.
            return (nil, nil)
        }
        return nil
    }

    private static func elapsedTime(_ value: String) -> TimeInterval? {
        let parts = value.split(separator: ":").compactMap { Double($0) }
        guard parts.count == 3, parts.allSatisfy({ $0 >= 0 }), parts[1] < 60, parts[2] < 60 else { return nil }
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    }

    /// Compatibility parser for read-only consumers of legacy labelled output and current tables.
    public static func referenceTokens(_ text: String) -> Set<String> {
        if let rows = try? references(text), !rows.isEmpty {
            return Set(rows.map(\.token))
        }
        return Set(text.split(separator: "\n").compactMap { line in
            let words = line.replacingOccurrences(of: ":", with: " : ").split(whereSeparator: \.isWhitespace)
            guard let index = words.firstIndex(of: "Token"), index + 2 < words.count,
                  words[index + 1] == ":", validToken(String(words[index + 2])) else { return nil }
            return String(words[index + 2])
        })
    }

    public static func stockAnchorPresent(_ text: String) -> Bool {
        text.split(separator: "\n").contains { line in
            let words = line.split(whereSeparator: \.isWhitespace)
            return Array(words) == ["anchor", "\"com.apple/*\""] || Array(words) == ["anchor", "\"com.apple/*\"", "all"]
        }
    }

    /// PF's per-rule Evaluations field, never the packet or byte counter.
    public static func canaryEvaluations(_ text: String) throws -> UInt64 {
        var found: UInt64?
        var isCanary = false
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("@") || trimmed.hasPrefix("pass ") || trimmed.hasPrefix("block ") {
                isCanary = trimmed.contains("label \"\(PacketFilterRenderer.canaryLabel)\"")
            }
            if isCanary, let range = trimmed.range(of: "Evaluations:") {
                let tail = trimmed[range.upperBound...].split(whereSeparator: \.isWhitespace)
                guard found == nil, let first = tail.first, let count = UInt64(first) else { throw DaemonFailure.pfVerification }
                found = count
                isCanary = false
            }
        }
        guard let found else { throw DaemonFailure.pfVerification }
        return found
    }
}
