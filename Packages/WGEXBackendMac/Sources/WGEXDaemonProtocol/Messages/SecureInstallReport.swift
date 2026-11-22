// SPDX-License-Identifier: MIT
/// Non-secret evidence returned by the daemon's own bundle inspection (ADR-025).
public struct SecureInstallReport: Codable, Sendable, Hashable {
    public enum Reason: String, Codable, Sendable, Hashable, CaseIterable {
        case bundleWritable, aclWritable, wrappingKeyUnavailable, notRootOwned, notInApplications, wrongBundle, identityMismatch,
             inspectionFailed
        /// An existing wrapping key was retained but its access repair could not be verified.
        case wrappingKeyRepairFailed
    }

    public enum State: Codable, Sendable, Hashable {
        case verified
        case needsAttention(Reason)
        case inProgress
    }

    public enum IdentityCheck: String, Codable, Sendable, Hashable {
        case matched, failed, unavailable
    }

    public var state: State
    public var bundlePath: String
    public var nonRootOwnedEntries: Int
    public var nonRootWritableEntries: Int
    public var isUnderApplications: Bool
    public var bundleIdentity: IdentityCheck
    public var daemonIdentity: IdentityCheck

    public init(
        state: State, bundlePath: String, nonRootOwnedEntries: Int = 0, nonRootWritableEntries: Int = 0,
        isUnderApplications: Bool, bundleIdentity: IdentityCheck = .unavailable, daemonIdentity: IdentityCheck = .unavailable,
    ) {
        self.state = state; self.bundlePath = bundlePath
        self.nonRootOwnedEntries = nonRootOwnedEntries; self.nonRootWritableEntries = nonRootWritableEntries
        self.isUnderApplications = isUnderApplications; self.bundleIdentity = bundleIdentity; self.daemonIdentity = daemonIdentity
    }
}
