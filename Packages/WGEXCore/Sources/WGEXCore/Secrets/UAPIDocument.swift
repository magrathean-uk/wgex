// SPDX-License-Identifier: MIT

/// A UAPI configuration document in a wiped buffer (02 §6.4). Phase-0 shape:
/// the encoder and golden files arrive with P2-05.
public struct UAPIDocument: ~Copyable, Sendable {
    /// The document bytes.
    public let bytes: SecretBytes

    /// Takes ownership of an encoded document.
    public init(bytes: consuming SecretBytes) {
        self.bytes = bytes
    }

    /// Length of the document in bytes.
    public var byteCount: Int {
        bytes.count
    }
}
