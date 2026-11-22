// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Source-compatible adapter to WGEXCore endpoint validation and formatting.
public nonisolated enum EndpointText {
    /// Parses without resolving hostnames; maps shared errors to field messages.
    public static func parse(_ text: String) -> Result<Endpoint, EndpointParseError> {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return .failure(.empty) }
        do { return try .success(Endpoint(trimmed)) }
        catch ConfigurationError.invalidPort { return .failure(.invalidPort) }
        catch {
            if !trimmed.contains(":") || (trimmed.hasPrefix("[") && trimmed.contains("]") && !trimmed.contains("]:")) {
                return .failure(.missingPort)
            }
            return .failure(.invalidHost)
        }
    }

    /// Brackets IPv6 literals through the shared formatter.
    public static func format(_ endpoint: Endpoint) -> String {
        endpoint.stringRepresentation
    }

    /// Strict dotted-quad compatibility query.
    public static func isDottedQuad(_ text: String) -> Bool {
        guard let address = try? IPAddressRange(text) else { return false }
        return !address.isIPv6 && !text.contains("/")
    }

    /// Host compatibility query using the shared validator.
    public static func isValidHost(_ host: String) -> Bool {
        (try? Endpoint(validatingHost: host, port: 1)) != nil
    }
}

/// Why an endpoint did not parse.
public nonisolated enum EndpointParseError: Error, Sendable, Hashable {
    /// Nothing was entered.
    case empty
    /// No port was given.
    case missingPort
    /// The port is not 1–65535.
    case invalidPort
    /// The host is not a valid name or literal.
    case invalidHost

    /// Field message.
    public var message: String {
        switch self {
        case .empty: "Enter an endpoint, for example vpn.example.com:51820"
        case .missingPort: "Add a port, for example vpn.example.com:51820"
        case .invalidPort: "Port must be 1–65535"
        case .invalidHost: "Invalid address"
        }
    }
}

/// Result of validating a text field.
public nonisolated enum FieldValidation: Sendable, Hashable {
    /// Nothing entered.
    case empty
    /// Valid.
    case valid
    /// Invalid, with a message.
    case invalid(String)

    /// Message to show, if any.
    public var message: String? {
        if case let .invalid(message) = self {
            return message
        }
        return nil
    }

    /// Spoken state.
    public var spoken: String {
        switch self {
        case .empty: "empty"
        case .valid: "valid"
        case let .invalid(message): message
        }
    }
}
