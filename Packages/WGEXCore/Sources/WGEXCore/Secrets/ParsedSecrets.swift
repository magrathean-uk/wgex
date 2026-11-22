// SPDX-License-Identifier: MIT
import Foundation

/// Uniquely owned raw keys, indexed by the public references in a profile.
/// This container has no printable or Codable conformance.
public struct ParsedSecrets: ~Copyable, Sendable {
    private let storage: SecretBytes
    public let references: [SecretRef: Range<Int>]

    /// Takes ownership of packed 32-byte keys; ranges must be valid and disjoint.
    public init(bytes: consuming SecretBytes, references: [SecretRef: Range<Int>]) throws(ConfigurationError) {
        let ranges = references.values.sorted { $0.lowerBound < $1.lowerBound }
        var end = 0
        for range in ranges {
            guard range.count == 32, range.lowerBound >= end, range.upperBound <= bytes.count else {
                throw .invalidSecretReference
            }
            end = range.upperBound
        }
        storage = bytes
        self.references = references
    }

    /// Borrow a key for the duration of the closure. The pointer must not escape.
    public func withKey<Result>(
        _ reference: SecretRef, _ body: (UnsafeRawBufferPointer) throws -> Result,
    ) throws -> Result {
        guard let range = references[reference] else { throw ConfigurationError.invalidSecretReference }
        return try storage.withUnsafeBytes { try body(UnsafeRawBufferPointer(rebasing: $0[range])) }
    }
}

public extension SecretRef {
    /// Public marker used in redacted configuration text; never contains key material.
    var placeholder: String {
        let identifier = switch self {
        case let .daemonStore(id): id.uuidString
        case let .keychain(persistentRef): persistentRef.base64EncodedString()
        }
        return "$WGEX_SECRET:\(identifier)$"
    }
}

/// Configuration text that may contain secrets. Access is scoped to a byte view.
public struct SecretText: ~Copyable, Sendable {
    public let bytes: SecretBytes

    public init(bytes: consuming SecretBytes) {
        self.bytes = bytes
    }

    public var byteCount: Int {
        bytes.count
    }
}

/// A public profile, its wiped keys and a redacted, losslessly restorable original.
public struct ParsedConfiguration: ~Copyable, Sendable {
    public var profile: TunnelProfile
    public let diagnostics: [ConfigDiagnostic]
    public let secrets: ParsedSecrets
    public let original: OriginalText

    public init(profile: TunnelProfile, diagnostics: [ConfigDiagnostic], secrets: consuming ParsedSecrets, original: OriginalText) {
        self.profile = profile
        self.diagnostics = diagnostics
        self.secrets = secrets
        self.original = original
    }
}
