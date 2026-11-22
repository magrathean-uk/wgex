// SPDX-License-Identifier: MIT

/// Failures creating or copying a ``SecretBytes`` buffer.
public enum SecretBytesError: Error, Sendable, Hashable {
    /// The requested length is negative or above ``SecretBytes/maximumCount``.
    case invalidLength(Int)
    /// `mmap` failed with the given `errno`.
    case allocationFailed(Int32)
    /// A copy did not fit the destination.
    case outOfBounds
}
