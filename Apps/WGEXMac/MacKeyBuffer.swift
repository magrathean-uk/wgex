// SPDX-License-Identifier: MIT

import WGEXCore

/// Wiped ownership wrapper required by ParsedSecrets.withKey's Copyable result.
/// It deliberately hides all stored properties from reflection.
public final class MacKeyBuffer: CustomStringConvertible, CustomReflectable {
    private let bytes: SecretBytes
    public init(_ bytes: consuming SecretBytes) {
        self.bytes = bytes
    }

    public var description: String {
        "MacKeyBuffer(<redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    public func copy() throws -> SecretBytes {
        try SecretBytes(parsing: bytes)
    }
}
