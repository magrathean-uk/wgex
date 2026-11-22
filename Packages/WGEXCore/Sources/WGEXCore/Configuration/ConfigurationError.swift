// SPDX-License-Identifier: MIT
import Foundation

/// Value construction failures contain no input text or secret material.
public enum ConfigurationError: Error, Codable, Sendable, Hashable {
    case invalidCIDR
    case invalidEndpoint
    case invalidPort
    case invalidLimits
    case invalidSecretReference
    case invalidDNS
    case unsupportedSchema(Int)
}

/// A configuration that cannot be installed, with structured diagnostics.
public struct ConfigValidationError: Error, Codable, Sendable, Hashable {
    public let diagnostics: [ConfigDiagnostic]

    public init(diagnostics: [ConfigDiagnostic]) {
        self.diagnostics = diagnostics
    }
}

/// Errors raised by the bounded configuration parser (`WgQuickParser`).
public enum ConfigParseError: Error, Codable, Sendable, Hashable {
    case diagnostics([ConfigDiagnostic])
    case invalidUTF8
}

/// Key failures never retain key bytes or CryptoKit error descriptions.
public enum KeyError: Error, Sendable, Hashable {
    case invalidLength(Int)
    case invalidEncoding
    case buffer(SecretBytesError)
    case derivationFailed
}
