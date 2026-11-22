// SPDX-License-Identifier: MIT
import Foundation

/// A local port or port range excluded from the tunnel (DEC-087 item a, reduced by DEC-126). It applies only to an app
/// that binds its sockets to the physical interface itself: the Mac packet filter then passes that port on the physical
/// interface while the kill switch is on. WGEX adds no route, NAT or redirection for it.
public struct PortExclusion: Codable, Sendable, Hashable, Comparable {
    /// The transport an entry covers; `nil` covers both.
    public enum Transport: String, Codable, Sendable, Hashable, CaseIterable { case tcp, udp }

    /// The widest inclusive range one entry may cover.
    public static let maximumRangeSize = 1024

    /// First port, 1 to 65535.
    public let lower: UInt16
    /// Last port, inclusive, at least `lower`.
    public let upper: UInt16
    /// TCP, UDP or, when `nil`, both.
    public let transport: Transport?

    /// A validated entry: 1 to 65535, `lower <= upper`, at most `maximumRangeSize` ports.
    public init(lower: UInt16, upper: UInt16? = nil, transport: Transport? = nil) throws(ConfigurationError) {
        let upper = upper ?? lower
        guard Self.isValid(lower: lower, upper: upper) else { throw .invalidPort }
        self.lower = lower; self.upper = upper; self.transport = transport
    }

    private static func isValid(lower: UInt16, upper: UInt16) -> Bool {
        lower > 0 && lower <= upper && Int(upper) - Int(lower) < maximumRangeSize
    }

    /// Parses `1911`, `1911/tcp` or `6881-6889/udp`. Text that does not start with a digit is not a port entry.
    public init(_ text: String) throws(ConfigurationError) {
        let parts = text.trimmingCharacters(in: .whitespaces).lowercased().split(separator: "/", omittingEmptySubsequences: false)
        guard (1 ... 2).contains(parts.count) else { throw .invalidPort }
        var transport: Transport?
        if parts.count == 2 {
            guard let named = Transport(rawValue: String(parts[1])) else { throw .invalidPort }
            transport = named
        }
        let bounds = parts[0].split(separator: "-", omittingEmptySubsequences: false)
        guard (1 ... 2).contains(bounds.count),
              let lower = Self.port(bounds[0]), let upper = bounds.count == 2 ? Self.port(bounds[1]) : Optional(lower)
        else { throw .invalidPort }
        try self.init(lower: lower, upper: upper, transport: transport)
    }

    /// Whether `text` is shaped like a port entry (starts with a digit and holds no dot or colon), so a malformed
    /// port is reported as a port rather than as a host name.
    public static func looksLikePort(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        return trimmed.first?.isASCII == true && trimmed.first?.isNumber == true && !trimmed.contains(".") && !trimmed.contains(":")
    }

    private static func port(_ text: Substring) -> UInt16? {
        guard !text.isEmpty, text.count <= 5, text.utf8.allSatisfy({ (48 ... 57).contains($0) }) else { return nil }
        return UInt16(text)
    }

    /// The canonical spelling used by export and the editor: `1911`, `1911/tcp`, `6881-6889/udp`.
    public var text: String {
        let ports = lower == upper ? String(lower) : "\(lower)-\(upper)"
        return transport.map { "\(ports)/\($0.rawValue)" } ?? ports
    }

    /// The transports this entry covers, TCP first.
    public var transports: [Transport] {
        transport.map { [$0] } ?? Transport.allCases
    }

    /// First port of the kernel's ephemeral range. Any app's outbound connection takes a random source port from
    /// 49152 to 65535, so an exclusion that touches it would pull unrelated flows out of the tunnel (M08-T17).
    public static let ephemeralStart: UInt16 = 49152

    /// Whether any port of the entry is in the ephemeral range 49152 to 65535.
    public var touchesEphemeralRange: Bool {
        upper >= Self.ephemeralStart
    }

    /// Whether `port` falls inside the range.
    public func contains(_ port: UInt16) -> Bool {
        (lower ... upper).contains(port)
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.lower, lhs.upper, lhs.transport?.rawValue ?? "") < (rhs.lower, rhs.upper, rhs.transport?.rawValue ?? "")
    }

    private enum CodingKeys: String, CodingKey { case lower, upper, transport }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let lower = try container.decode(UInt16.self, forKey: .lower)
        let upper = try container.decodeIfPresent(UInt16.self, forKey: .upper) ?? lower
        guard Self.isValid(lower: lower, upper: upper) else {
            throw DecodingError.dataCorruptedError(forKey: .lower, in: container, debugDescription: "port exclusion")
        }
        self.lower = lower; self.upper = upper
        transport = try container.decodeIfPresent(Transport.self, forKey: .transport)
    }
}
