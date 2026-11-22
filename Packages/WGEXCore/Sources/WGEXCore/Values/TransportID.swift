// SPDX-License-Identifier: MIT

import Foundation

/// Identifier of a transport candidate in a profile (02 §8.1). It is 16 bytes
/// on the secrets wire layout.
public struct TransportID: Codable, Sendable, Hashable {
    /// The identifier.
    public let rawValue: UUID

    /// Wraps an identifier.
    public init(rawValue: UUID = UUID()) {
        self.rawValue = rawValue
    }

    /// Decodes a bare UUID.
    public init(from decoder: any Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(UUID.self)
    }

    /// Encodes as a bare UUID.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
