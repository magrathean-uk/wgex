// SPDX-License-Identifier: MIT
import Foundation

/// A Curve25519 public key (32 bytes); public material may be displayed and encoded.
public struct PublicKey: Codable, Sendable, Hashable {
    /// Key length in bytes.
    public static let byteCount = 32

    package static let placeholder = PublicKey(unchecked: Data(count: byteCount))

    private init(unchecked data: Data) {
        rawValue = data
    }

    /// The raw key bytes.
    public let rawValue: Data

    /// Wraps 32 raw bytes.
    public init(rawValue: Data) throws(KeyFormatError) {
        guard rawValue.count == Self.byteCount else {
            throw .invalidLength(rawValue.count)
        }
        self.rawValue = rawValue
    }

    /// Parses standard base64 text.
    public init(base64: String) throws(KeyFormatError) {
        do { self = try Array(base64.utf8).withUnsafeBytes { try PublicKey(parsing: $0, encoding: .base64) } }
        catch let error as KeyFormatError { throw error }
        catch { throw .invalidBase64 }
    }

    /// Decodes raw bytes and validates their length.
    public init(from decoder: any Decoder) throws {
        let data = try decoder.singleValueContainer().decode(Data.self)
        try self.init(rawValue: data)
    }

    /// Standard base64 text.
    public var base64: String {
        rawValue.base64EncodedString()
    }

    /// Encodes the raw bytes.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public extension PublicKey {
    /// Parses a byte view without a String intermediary.
    init(parsing source: UnsafeRawBufferPointer, encoding: KeyEncoding) throws(KeyFormatError) {
        var data = Data(count: Self.byteCount)
        do {
            try data.withUnsafeMutableBytes { try ByteCodec.decode(source, into: $0, encoding: encoding) }
        } catch { throw .invalidBase64 }
        try self.init(rawValue: data)
    }

    func encode(into destination: UnsafeMutableRawBufferPointer, encoding: KeyEncoding) throws(ByteCodecError) {
        do { try rawValue.withUnsafeBytes { try ByteCodec.encode($0, into: destination, encoding: encoding) } }
        catch let error as ByteCodecError { throw error }
        catch { throw .invalidEncoding }
    }
}
