// SPDX-License-Identifier: MIT

/// Failures parsing a public key.
public enum KeyFormatError: Error, Sendable, Hashable {
    /// The key is not 32 bytes long.
    case invalidLength(Int)
    /// The text is not valid base64.
    case invalidBase64
}
