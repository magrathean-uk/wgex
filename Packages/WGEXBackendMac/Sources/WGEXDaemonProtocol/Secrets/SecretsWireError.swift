// SPDX-License-Identifier: MIT

import WGEXCore

/// Failures writing or parsing the secrets wire layout.
public enum SecretsWireError: Error, Sendable, Hashable {
    /// The version byte is not ``SecretsWireLayout/version``.
    case unsupportedVersion(UInt8)
    /// The bytes end before the layout does.
    case truncated
    /// Bytes remain after the layout.
    case trailingBytes
    /// A key is not 32 bytes long.
    case invalidKeyLength(Int)
    /// A carrier credential is longer than a u16 length allows.
    case credentialTooLong(Int)
    /// More entries than a u16 count allows.
    case tooManyEntries
    /// The same peer appears twice.
    case duplicatePeer
    /// The same transport appears twice.
    case duplicateCarrier
    /// A peer entry was appended after the carrier section started.
    case peerAfterCarrier
    /// The buffer could not be allocated.
    case allocation(SecretBytesError)
}
