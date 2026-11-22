// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Reference wrapper permits uniquely owned bytes inside a peer dictionary.
/// Reflection and description deliberately expose no stored properties.
package final class EditorSecret: CustomStringConvertible, CustomReflectable {
    private let bytes: SecretBytes

    package init(_ bytes: consuming SecretBytes) {
        self.bytes = bytes
    }

    package var description: String {
        "EditorSecret(<redacted>)"
    }

    package var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    package func copy() throws -> SecretBytes {
        try SecretBytes(parsing: bytes)
    }

    package func equals(_ other: EditorSecret) -> Bool {
        bytes.constantTimeEquals(other.bytes)
    }

    /// Only the SecretField's reveal/copy callback may request a String.
    package func fieldText() -> String? {
        do {
            var encoded = try SecretBytes(zeroedCount: 44)
            try bytes.withUnsafeBytes { source in
                try encoded.withUnsafeMutableBytes { try ByteCodec.encode(source, into: $0, encoding: .base64) }
            }
            return encoded.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        } catch { return nil }
    }

    package func write(into target: inout SecretBytes, offset: Int) throws {
        try bytes.copyBytes(into: &target, at: offset)
    }
}
