// SPDX-License-Identifier: MIT

import Foundation

/// Binary property-list coding for every XPC message (02 §5): never JSON,
/// bounded to ``maximumMessageSize``.
public enum WireCodec {
    /// Largest accepted message (1 MiB).
    public static let maximumMessageSize = 1 << 20

    private static let binaryPlistMagic = Data("bplist".utf8)

    /// Encodes `value` as a binary property list.
    public static func encode(_ value: some Encodable) throws(DaemonError) -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data: Data
        do {
            data = try encoder.encode(value)
        } catch {
            throw .malformedMessage
        }
        guard data.count <= maximumMessageSize else {
            throw .messageTooLarge(data.count)
        }
        return data
    }

    /// Decodes a binary property list; XML and other formats are refused.
    public static func decode<Value: Decodable>(_: Value.Type, from data: Data) throws(DaemonError) -> Value {
        guard data.count <= maximumMessageSize else {
            throw .messageTooLarge(data.count)
        }
        guard data.starts(with: binaryPlistMagic) else {
            throw .malformedMessage
        }
        do {
            return try PropertyListDecoder().decode(Value.self, from: data)
        } catch {
            throw .malformedMessage
        }
    }
}
