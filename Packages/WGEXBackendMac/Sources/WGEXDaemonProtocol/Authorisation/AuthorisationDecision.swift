// SPDX-License-Identifier: MIT

/// Why a request was denied.
public enum AuthorisationDenial: String, Codable, Sendable, Hashable {
    /// The caller does not own the profile.
    case notOwner
    /// The caller is not the console user (and not root).
    case notConsoleUser
    /// The admin right is required.
    case adminRightRequired
    /// The client build is not newer than the daemon build.
    case clientNotNewer
    /// The request kind has no rule (fail closed).
    case noRule
    /// Only the WGEX app may send this request, not the CLI.
    case notAppClient
}

/// Outcome of ``AuthorisationTable/decide(request:callerUID:isConsoleUser:hasAdminRight:ownerUID:currentSettings:clientIsNewer:)``.
public enum AuthorisationDecision: Sendable, Hashable {
    /// The request may proceed.
    case allow
    /// The request is refused.
    case deny(AuthorisationDenial)
}
