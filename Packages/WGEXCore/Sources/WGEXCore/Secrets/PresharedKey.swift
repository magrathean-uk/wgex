// SPDX-License-Identifier: MIT

/// A uniquely owned WireGuard preshared key, never Codable or printable.
public struct PresharedKey: ~Copyable, Sendable {
    private let bytes: SecretBytes

    public init(bytes: consuming SecretBytes) throws(KeyError) {
        guard bytes.count == PublicKey.byteCount else { throw .invalidLength(bytes.count) }
        self.bytes = consume bytes
    }

    public init(parsing source: borrowing SecretBytes, encoding: KeyEncoding = .raw) throws(KeyError) {
        bytes = try KeyMaterial.decode(source, encoding: encoding)
    }

    public func encode(into destination: inout SecretBytes, encoding: KeyEncoding = .raw) throws(KeyError) {
        try KeyMaterial.encode(bytes, into: &destination, encoding: encoding)
    }
}
