// SPDX-License-Identifier: MIT

public struct ConfigDiagnostic: Sendable, Hashable, Codable {
    public enum Severity: String, Codable, Sendable, Hashable { case error, warning }
    public enum Code: String, Codable, Sendable, Hashable, CaseIterable {
        case unsupportedSetting, invalidDNS, invalidKeepalive
        case unknownKey, ignoredHook, amneziaField, duplicateKey, duplicatePeer, invalidCIDR
        case invalidKey, invalidEndpoint, invalidPort, invalidMTU, limitExceeded, controlCharacter, dnsOutsideAllowedIPs
        case noAddresses, noPeers, ipv6PolicyRequired, keyInUseElsewhere, carrierRequiresSinglePeer, keepaliveClampedByCarrier
        case exclusionPortEphemeral
    }

    public var severity: Severity
    public var code: Code
    public var line: Int?
    public var message: String

    public init(severity: Severity, code: Code, line: Int? = nil, message: String? = nil) {
        self.severity = severity; self.code = code; self.line = line
        self.message = message ?? UserStrings.diagnostic(code)
    }
}

/// Parser resource bounds. Callers may tighten, never raise, the canonical caps.
public struct ParseLimits: Sendable, Hashable {
    public static let `default` = ParseLimits()
    public let maximumBytes: Int
    public let maximumLines: Int
    public let maximumPeers: Int
    public let maximumAllowedIPs: Int
    public let maximumDNS: Int
    public let maximumNameCharacters: Int

    public init() {
        maximumBytes = 256 * 1024; maximumLines = 4096; maximumPeers = 1024
        maximumAllowedIPs = 4096; maximumDNS = 64; maximumNameCharacters = 128
    }

    public init(
        maximumBytes: Int, maximumLines: Int, maximumPeers: Int, maximumAllowedIPs: Int,
        maximumDNS: Int, maximumNameCharacters: Int,
    ) throws(ConfigurationError) {
        guard (1 ... 256 * 1024).contains(maximumBytes), (1 ... 4096).contains(maximumLines),
              (1 ... 1024).contains(maximumPeers), (1 ... 4096).contains(maximumAllowedIPs),
              (1 ... 64).contains(maximumDNS), (1 ... 128).contains(maximumNameCharacters)
        else { throw .invalidLimits }
        self.maximumBytes = maximumBytes; self.maximumLines = maximumLines; self.maximumPeers = maximumPeers
        self.maximumAllowedIPs = maximumAllowedIPs; self.maximumDNS = maximumDNS; self.maximumNameCharacters = maximumNameCharacters
    }
}
