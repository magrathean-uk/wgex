// SPDX-License-Identifier: MIT

/// Registration state of the Mac daemon; an unrecorded bundled plist is notRegistered.
public enum ServiceState: String, Codable, Sendable, Hashable, CaseIterable {
    /// Not registered.
    case notRegistered
    /// Registered and allowed to run.
    case enabled
    /// Registered; the user must approve it in System Settings.
    case requiresApproval
    /// The daemon plist was not found in the bundle.
    case notFound
}
