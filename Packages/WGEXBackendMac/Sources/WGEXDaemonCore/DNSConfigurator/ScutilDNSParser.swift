// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public struct DNSResolverRecord: Sendable, Equatable {
    public var domain = ""
    public var servers: [String] = []
    public var order: Int?
    public var interfaceName: String?
    public var interfaceIndex: UInt32?
    public var scoped = false
    public var supplemental = false
    public init() {}
}

/// Parses documented scutil --dns text, including scoped and service-specific sections.
/// Malformed records cannot provide positive evidence of precedence.
public enum ScutilDNSParser {
    public static func parse(_ text: String) -> [DNSResolverRecord] {
        var records: [DNSResolverRecord] = [], record: DNSResolverRecord?
        var scopedSection = false
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("DNS configuration") {
                if let current = record {
                    records.append(current); record = nil
                }
                scopedSection = line.contains("scoped") || line.contains("service-specific")
            } else if line.hasPrefix("resolver #") {
                if let current = record {
                    records.append(current)
                }
                record = DNSResolverRecord(); record?.scoped = scopedSection
            } else if let colon = line.firstIndex(of: ":"), record != nil {
                let field = line[..<colon].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                apply(field: field, value: value, scopedSection: scopedSection, to: &record)
            }
        }
        if let record {
            records.append(record)
        }
        return records
    }

    private static func apply(field: String, value: String, scopedSection: Bool, to record: inout DNSResolverRecord?) {
        switch field {
        case "domain": record?.domain = value
        case "order": record?.order = Int(value)
        case "if_index":
            record?.interfaceName = ""
            record?.interfaceIndex = value.split(whereSeparator: \.isWhitespace).first.flatMap { UInt32($0) }
            if let start = value.firstIndex(of: "("), let end = value.lastIndex(of: ")"), start < end {
                record?.interfaceName = String(value[value.index(after: start) ..< end])
            }
        case "flags":
            record?.scoped = scopedSection || value.contains("Scoped")
            record?.supplemental = value.contains("Supplemental")
        default:
            if field.hasPrefix("nameserver[") {
                record?.servers.append(value)
            }
        }
    }

    public static func verifies(
        _ expected: SyntheticDNSValue, in text: String, interfaceName: String? = nil, interfaceIndex: UInt32? = nil,
    ) -> Bool {
        let records = parse(text).filter { !$0.scoped && !$0.servers.isEmpty }
        let configuration = expected.configuration
        return configuration.matchDomains.allSatisfy { domain in
            let applicable = records.filter { $0.domain == domain }
            guard let ours = applicable
                .first(where: {
                    $0.servers == configuration.servers && $0.supplemental &&
                        ($0.interfaceName == nil || ($0.interfaceName == interfaceName && $0.interfaceIndex == interfaceIndex))
                }),
                let order = ours.order else { return false }
            // Refuse ties: the WGEX resolver must be unambiguously first, independent of textual record order.
            return applicable.allSatisfy { $0 == ours || ($0.order.map { $0 > order } ?? false) }
        }
    }
}
