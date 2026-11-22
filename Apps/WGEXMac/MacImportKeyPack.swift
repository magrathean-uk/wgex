// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// Owns wiped copies across the import review's synchronous callback boundary.
    @MainActor
    public final class MacImportKeyPack {
        private let bytes: MacKeyBuffer
        private let references: [SecretRef: Range<Int>]

        /// Copies only parser-owned keys into wiped buffers for the asynchronous owner.
        public init(profile: TunnelProfile, secrets: borrowing ParsedSecrets) throws {
            let refs = [profile.secrets.privateKey] + Array(profile.secrets.presharedKeys.values)
            var packed = try SecretBytes(zeroedCount: refs.count * 32)
            var ranges: [SecretRef: Range<Int>] = [:]
            for (index, ref) in refs.enumerated() {
                let key = try secrets.withKey(ref) { try MacKeyBuffer(SecretBytes(copying: $0)) }
                let copy = try key.copy()
                try copy.copyBytes(into: &packed, at: index * 32)
                ranges[ref] = (index * 32) ..< (index * 32 + 32)
            }
            bytes = MacKeyBuffer(consume packed); references = ranges
        }

        /// Reconstructs parser references without a printable key representation.
        public func secrets() throws -> ParsedSecrets {
            try ParsedSecrets(bytes: bytes.copy(), references: references)
        }
    }
#endif
