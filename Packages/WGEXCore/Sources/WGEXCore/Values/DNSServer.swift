// SPDX-License-Identifier: MIT
import Foundation

/// A numeric resolver address. Search domains belong in `searchDomains`.
public struct DNSServer: Codable, Sendable, Hashable {
    public let address: IPAddressRange

    public init(_ text: String) throws(ConfigurationError) {
        guard !text.contains("/") else { throw .invalidDNS }
        do { address = try IPAddressRange(text) } catch { throw .invalidDNS }
    }

    public var stringRepresentation: String {
        address.address
    }

    public init(from decoder: any Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(stringRepresentation)
    }
}
