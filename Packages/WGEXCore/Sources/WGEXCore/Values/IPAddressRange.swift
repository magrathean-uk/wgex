// SPDX-License-Identifier: MIT
import Foundation
import Network

/// A literal IP address and prefix; host bits are retained for interface addresses.
public struct IPAddressRange: Codable, Sendable, Hashable, Comparable, CustomStringConvertible {
    public let address: String
    public let networkPrefixLength: UInt8
    public let isIPv6: Bool
    private let octets: [UInt8]

    /// A bare address uses its full-width host prefix. Scope identifiers are rejected.
    public init(_ text: String) throws(ConfigurationError) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard (1 ... 2).contains(parts.count), !parts[0].contains("%") else { throw .invalidCIDR }
        let literal = String(parts[0])
        let bytes: [UInt8]
        let canonical: String
        let v6: Bool
        if let ip = IPv4Address(literal) {
            guard Self.isStrictIPv4(literal) else { throw .invalidCIDR }
            bytes = Array(ip.rawValue); canonical = ip.debugDescription; v6 = false
        } else if let ip = IPv6Address(literal) {
            guard Self.isStrictLiteral(literal) else { throw .invalidCIDR }
            bytes = Array(ip.rawValue); canonical = ip.debugDescription; v6 = true
        } else {
            throw .invalidCIDR
        }
        let width = v6 ? 128 : 32
        let prefix: Int
        if parts.count == 2 {
            guard !parts[1].isEmpty, parts[1].utf8.allSatisfy({ (48 ... 57).contains($0) }),
                  let parsed = Int(parts[1]), (0 ... width).contains(parsed)
            else { throw .invalidCIDR }
            prefix = parsed
        } else {
            prefix = width
        }
        address = canonical; networkPrefixLength = UInt8(prefix); isIPv6 = v6; octets = bytes
    }

    /// Network.framework accepts historical IPv4 shorthand and octal forms; public literals do not.
    package static func isStrictLiteral(_ text: String) -> Bool {
        if text.contains(":") {
            guard IPv6Address(text) != nil else { return false }
            if text.contains(".") {
                guard let tail = text.split(separator: ":").last else { return false }
                return isStrictIPv4(String(tail))
            }
            return true
        }
        return isStrictIPv4(text) && IPv4Address(text) != nil
    }

    package static func isStrictIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            !$0.isEmpty && ($0.count == 1 || $0.first != "0") && $0.utf8.allSatisfy { (48 ... 57).contains($0) } && UInt8($0) != nil
        }
    }

    package var ipv4Bounds: ClosedRange<UInt64>? {
        guard !isIPv6 else { return nil }
        let value = octets.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let hostMask = (UInt64(1) << (32 - Int(networkPrefixLength))) - 1
        return (value & ~hostMask) ... (value | hostMask)
    }

    public var stringRepresentation: String {
        "\(address)/\(networkPrefixLength)"
    }

    /// Whether an address (or the entirety of a more specific range) lies inside this prefix.
    public func contains(_ other: IPAddressRange) -> Bool {
        guard isIPv6 == other.isIPv6, networkPrefixLength <= other.networkPrefixLength else { return false }
        for bit in 0 ..< Int(networkPrefixLength) {
            let mask = UInt8(1 << (7 - bit % 8))
            if octets[bit / 8] & mask != other.octets[bit / 8] & mask {
                return false
            }
        }
        return true
    }

    public init(from decoder: any Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(stringRepresentation)
    }
}

public extension IPAddressRange {
    /// Every IPv4 address.
    static let allIPv4 = IPAddressRange(bytes: [0, 0, 0, 0], prefixLength: 0)
    /// Every IPv6 address.
    static let allIPv6 = IPAddressRange(bytes: Array(repeating: 0, count: 16), prefixLength: 0)
    /// RFC 1918 and IPv4 link-local prefixes used by the private-network exclusion.
    static let privateIPv4: [IPAddressRange] = [
        IPAddressRange(bytes: [10, 0, 0, 0], prefixLength: 8),
        IPAddressRange(bytes: [172, 16, 0, 0], prefixLength: 12),
        IPAddressRange(bytes: [192, 168, 0, 0], prefixLength: 16),
        IPAddressRange(bytes: [169, 254, 0, 0], prefixLength: 16),
    ]

    /// Creates a literal from public bytes, rejecting invalid widths and prefixes without clamping.
    init(validatingBytes bytes: [UInt8], prefixLength: Int) throws(ConfigurationError) {
        guard bytes.count == 4 || bytes.count == 16, (0 ... bytes.count * 8).contains(prefixLength) else { throw .invalidCIDR }
        self.init(bytes: bytes, prefixLength: prefixLength)
        guard !address.isEmpty else { throw .invalidCIDR }
    }

    /// Trusted package construction from exactly four or sixteen octets.
    package init(bytes: [UInt8], prefixLength: Int) {
        precondition(bytes.count == 4 || bytes.count == 16)
        octets = bytes
        isIPv6 = bytes.count == 16
        networkPrefixLength = UInt8(min(max(prefixLength, 0), bytes.count * 8))
        address = (isIPv6 ? IPv6Address(Data(bytes))?.debugDescription : IPv4Address(Data(bytes))?.debugDescription) ?? ""
    }

    /// Address bytes, including any host bits.
    var bytes: [UInt8] {
        octets
    }

    /// Prefix width as an integer.
    var prefixLength: Int {
        Int(networkPrefixLength)
    }

    /// Canonical literal and prefix; retains interface host bits.
    var description: String {
        stringRepresentation
    }

    /// Whether the literal has bits set beyond its prefix.
    var hasHostBits: Bool {
        network.octets != octets
    }

    /// The same prefix with host bits cleared.
    var network: IPAddressRange {
        var masked = octets
        for index in masked.indices {
            let bits = min(max(prefixLength - index * 8, 0), 8)
            masked[index] &= bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
        return IPAddressRange(bytes: masked, prefixLength: prefixLength)
    }

    /// Whether these prefixes share any address.
    func overlaps(_ other: IPAddressRange) -> Bool {
        contains(other) || other.contains(self)
    }

    /// Splits the canonical network into equal halves; host prefixes cannot split.
    func halves() -> (IPAddressRange, IPAddressRange)? {
        guard prefixLength < octets.count * 8 else { return nil }
        let lower = IPAddressRange(bytes: network.octets, prefixLength: prefixLength + 1)
        var upper = lower.octets
        upper[prefixLength / 8] |= UInt8(0x80 >> (prefixLength % 8))
        return (lower, IPAddressRange(bytes: upper, prefixLength: prefixLength + 1))
    }

    /// Removes an overlapping prefix, retaining canonical, disjoint networks.
    func subtracting(_ excluded: IPAddressRange) -> [IPAddressRange] {
        if excluded.contains(self) {
            return []
        }
        guard contains(excluded), let (lower, upper) = halves() else { return [network] }
        return lower.subtracting(excluded) + upper.subtracting(excluded)
    }

    /// Subtracts all exclusions and returns the smallest sorted set of prefixes.
    static func subtracting(_ ranges: [IPAddressRange], excluding excluded: [IPAddressRange]) -> [IPAddressRange] {
        var remaining = merged(ranges)
        for exclusion in merged(excluded) {
            remaining = remaining.flatMap { $0.subtracting(exclusion) }
        }
        return merged(remaining)
    }

    /// Canonicalises, removes contained prefixes and recursively joins adjacent siblings.
    static func merged(_ ranges: [IPAddressRange]) -> [IPAddressRange] {
        var result: [IPAddressRange] = []
        for range in Set(ranges.map(\.network)).sorted() {
            if result.last?.contains(range) == true {
                continue
            }
            var candidate = range
            while let last = result.last, last.isIPv6 == candidate.isIPv6,
                  last.prefixLength == candidate.prefixLength, candidate.prefixLength > 0
            {
                let parent = IPAddressRange(bytes: candidate.octets, prefixLength: candidate.prefixLength - 1).network
                guard parent.contains(last) else { break }
                result.removeLast()
                candidate = parent
            }
            result.append(candidate)
        }
        return result
    }

    /// Orders IPv4 before IPv6, then octets and prefix width.
    static func < (lhs: IPAddressRange, rhs: IPAddressRange) -> Bool {
        if lhs.octets.count != rhs.octets.count {
            return lhs.octets.count < rhs.octets.count
        }
        if lhs.octets != rhs.octets {
            return lhs.octets.lexicographicallyPrecedes(rhs.octets)
        }
        return lhs.networkPrefixLength < rhs.networkPrefixLength
    }
}
