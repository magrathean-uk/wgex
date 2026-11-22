// SPDX-License-Identifier: MIT
import Foundation

/// Per-tunnel exclusions (DEC-087): destinations whose traffic leaves on the physical interface, not the tunnel, while the
/// tunnel is up. Addresses and ranges are literal; host names resolve at activation and on reconnect or network change.
/// Local ports (M08-T02) are a further list that only the Mac packet filter applies; absent lists decode as empty.
public struct TunnelExclusions: Codable, Sendable, Hashable {
    /// The most entries one tunnel may hold, counting addresses and host names together.
    public static let maximumEntries = 64
    /// The longest host name, in UTF-8 bytes (RFC 1035 presentation form without the trailing dot).
    public static let maximumHostNameLength = 253
    /// The most addresses one host name contributes per resolution.
    public static let maximumAddressesPerHost = 8
    /// The most port entries one tunnel may hold; counted apart from addresses and host names.
    public static let maximumPortEntries = 16

    /// The whole-line comment key that carries exclusions in wg-quick text, in [Interface]; other apps ignore comments.
    public static let wgQuickKey = "WGEX-Exclude"

    /// No exclusions.
    public static let empty = TunnelExclusions()

    /// Literal addresses and CIDR ranges, IPv4 and IPv6, canonical network form.
    public var ranges: [IPAddressRange]
    /// Lower-case host names.
    public var hostNames: [String]
    /// Local ports passed on the physical interface for apps bound to it (Mac only; DEC-126).
    public var ports: [PortExclusion]

    public init(ranges: [IPAddressRange] = [], hostNames: [String] = [], ports: [PortExclusion] = []) {
        self.ranges = ranges; self.hostNames = hostNames; self.ports = ports
    }

    /// Whether nothing is excluded.
    public var isEmpty: Bool {
        ranges.isEmpty && hostNames.isEmpty && ports.isEmpty
    }

    /// Address and host-name count used by `maximumEntries`; ports have their own limit.
    public var count: Int {
        ranges.count + hostNames.count
    }

    /// One user-entered exclusion.
    public enum Entry: Sendable, Hashable {
        case range(IPAddressRange)
        case hostName(String)
        case port(PortExclusion)

        /// The canonical spelling used by export and the editor.
        public var text: String {
            switch self {
            case let .range(range): range.prefixLength == range.bytes.count * 8 ? range.address : range.stringRepresentation
            case let .hostName(name): name
            case let .port(port): port.text
            }
        }
    }

    /// Every entry, ranges first, then host names, then ports, in stored order.
    public var entries: [Entry] {
        ranges.map(Entry.range) + hostNames.map(Entry.hostName) + ports.map(Entry.port)
    }

    /// Parses one entry: an IPv4 or IPv6 address, a CIDR range (host bits are cleared), a host name, or a local port
    /// (`1911`, `1911/tcp`, `6881-6889/udp`). Port-shaped text that is not a valid port throws `invalidPort`.
    public static func entry(_ text: String) throws(ConfigurationError) -> Entry {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if let range = try? IPAddressRange(trimmed) {
            return .range(range.network)
        }
        if PortExclusion.looksLikePort(trimmed) {
            return try .port(PortExclusion(trimmed))
        }
        // A string that looks numeric or carries a prefix is a malformed address, never a host name.
        guard !trimmed.contains("/"), !trimmed.contains(":"), trimmed.utf8.count <= maximumHostNameLength,
              PublicFieldSafety.isSearchDomain(trimmed)
        else { throw .invalidCIDR }
        let name = trimmed.lowercased()
        return .hostName(name.hasSuffix(".") ? String(name.dropLast()) : name)
    }

    /// Builds the value from entry texts, keeping the first of any duplicates.
    public init(entries texts: [String]) throws(ConfigurationError) {
        self.init()
        for text in texts {
            try append(Self.entry(text))
        }
    }

    /// Appends an entry unless an equal one is already present.
    public mutating func append(_ entry: Entry) {
        switch entry {
        case let .range(range): if !ranges.contains(range) {
                ranges.append(range)
            }
        case let .hostName(name): if !hostNames.contains(name) {
                hostNames.append(name)
            }
        case let .port(port): if !ports.contains(port) {
                ports.append(port)
            }
        }
    }

    private enum CodingKeys: String, CodingKey { case ranges, hostNames, ports }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ranges = try container.decodeIfPresent([IPAddressRange].self, forKey: .ranges) ?? []
        hostNames = try container.decodeIfPresent([String].self, forKey: .hostNames) ?? []
        ports = try container.decodeIfPresent([PortExclusion].self, forKey: .ports) ?? []
    }
}

public extension TunnelExclusions {
    /// Literal ranges plus the given resolved addresses, canonical, deduplicated and sorted; never a default route.
    func effectiveRanges(resolved: [IPAddressRange] = []) -> [IPAddressRange] {
        Array(Set((ranges + resolved).filter { $0.prefixLength > 0 }.map(\.network))).sorted()
    }

    /// The tunnel routes left after removing the excluded ranges from `routes`. A family without exclusions keeps its
    /// routes exactly as given; a family with exclusions is canonicalised, and a default route stays split into halves so
    /// it never replaces the physical default route.
    static func carve(_ routes: [IPAddressRange], excluding excluded: [IPAddressRange]) -> [IPAddressRange] {
        var result: [IPAddressRange] = []
        for v6 in [false, true] {
            let family = routes.filter { $0.isIPv6 == v6 }
            let removed = excluded.filter { $0.isIPv6 == v6 && $0.prefixLength > 0 }
            guard !removed.isEmpty, !family.isEmpty else {
                result += family
                continue
            }
            for range in IPAddressRange.subtracting(family, excluding: removed) {
                if range.prefixLength == 0, let (lower, upper) = range.halves() {
                    result += [lower, upper]
                } else {
                    result.append(range)
                }
            }
        }
        return result
    }
}
