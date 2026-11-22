// SPDX-License-Identifier: MIT

/// Daemon- or provider-allocated tunnel generation (02 §4.2). A newer
/// generation cancels in-flight work of older ones.
public struct Generation: Codable, Sendable, Hashable, Comparable {
    /// The first generation.
    public static let initial = Generation(rawValue: 1)

    /// Monotonic counter value.
    public let rawValue: UInt64

    /// Wraps a counter value.
    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    /// Decodes a bare integer.
    public init(from decoder: any Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(UInt64.self)
    }

    /// The following generation.
    public func next() -> Generation {
        Generation(rawValue: rawValue &+ 1)
    }

    /// Encodes as a bare integer.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// Orders by counter value.
    public static func < (lhs: Generation, rhs: Generation) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
