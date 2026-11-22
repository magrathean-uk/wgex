// SPDX-License-Identifier: MIT

/// The rules of the authorisation table (02 §5). The uid and audit session
/// always come from the connection, never from the message body.
public enum AuthorisationRule: Sendable, Hashable {
    /// Any client that passed the code-signing requirement.
    case authenticatedClient
    /// The profile owner's uid only; no cross-uid access in v1.
    case owner
    /// Owner uid and console user, or root.
    case ownerAndConsoleUserOrRoot
    /// Console user or root.
    case consoleUserOrRoot
    /// The admin right `manage-protection`.
    case adminRight
    /// The admin right and a client build newer than the daemon's.
    case adminRightAndNewerClient
    /// Tightening: owner uid and console user. Loosening (lockdown off,
    /// allow-LAN on, captive seconds changed): the admin right.
    case globalSettings
    /// Console user and the app's signing identifier (not the CLI); root gets no exemption (ADR-030).
    case consoleUserApp
}
