// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation

/// A uniquely owned WireGuard private key. No Codable or printable conformance.
public struct PrivateKey: ~Copyable, Sendable {
    private var bytes: SecretBytes

    /// Takes ownership; imported keys retain their bytes. X25519 clamps during derivation.
    public init(bytes: consuming SecretBytes) throws(KeyError) {
        guard bytes.count == PublicKey.byteCount else { throw .invalidLength(bytes.count) }
        self.bytes = consume bytes
    }

    public init(parsing source: borrowing SecretBytes, encoding: KeyEncoding = .raw) throws(KeyError) {
        bytes = try KeyMaterial.decode(source, encoding: encoding)
    }

    /// Explicit byte-buffer export; destination length must match the encoding.
    public func encode(into destination: inout SecretBytes, encoding: KeyEncoding = .raw) throws(KeyError) {
        try KeyMaterial.encode(bytes, into: &destination, encoding: encoding)
    }

    /// CryptoKit's RNG is called unconditionally in Debug and Release.
    public static func generate() throws(KeyError) -> PrivateKey {
        var transient = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        do {
            var secret = try SecretBytes(wiping: &transient)
            secret.withUnsafeMutableBytes {
                $0[0] &= 248; $0[31] &= 127; $0[31] |= 64
            }
            return try PrivateKey(bytes: consume secret)
        } catch let error as SecretBytesError { throw .buffer(error) }
        catch let error as KeyError { throw error }
        catch { throw .derivationFailed }
    }

    public func publicKey() throws(KeyError) -> PublicKey {
        do {
            return try bytes.withUnsafeBytes { raw in
                let derived = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw).publicKey.rawRepresentation
                return try PublicKey(rawValue: derived)
            }
        } catch { throw .derivationFailed }
    }
}

/// Shared secret-buffer codec plumbing; no intermediate secret arrays or strings.
package enum KeyMaterial {
    package static func decode(_ source: borrowing SecretBytes, encoding: KeyEncoding) throws(KeyError) -> SecretBytes {
        do {
            var result = try SecretBytes(zeroedCount: PublicKey.byteCount)
            try source.withUnsafeBytes { input in
                try result.withUnsafeMutableBytes { output in try ByteCodec.decode(input, into: output, encoding: encoding) }
            }
            return result
        } catch let error as SecretBytesError { throw .buffer(error) }
        catch { throw .invalidEncoding }
    }

    package static func encode(
        _ source: borrowing SecretBytes, into destination: inout SecretBytes, encoding: KeyEncoding,
    ) throws(KeyError) {
        do {
            try source.withUnsafeBytes { input in
                try destination.withUnsafeMutableBytes { output in try ByteCodec.encode(input, into: output, encoding: encoding) }
            }
        } catch { throw .invalidEncoding }
    }
}
