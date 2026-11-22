// SPDX-License-Identifier: MIT
/// Why secure install needs attention (ADR-025).
public enum SecureInstallIssue: String, CaseIterable, Sendable, Hashable {
    /// WGEX is not in the Applications folder.
    case notInApplications
    /// Bundle entries can be changed by a non-root user.
    case bundleWritable
    /// The privileged service could not be verified against this app.
    case serviceNotVerified
    /// The privileged service is older than this app.
    case serviceOutdated
}

/// Secure install state shown in onboarding and Settings → Service.
public enum SecureInstallState: Sendable, Hashable {
    /// The service is unavailable; no new install measurement has been received.
    case notReporting
    /// Verification is running.
    case checking
    /// App location and privileged service verified.
    case verified
    /// Something needs the user.
    case needsAttention(SecureInstallIssue)

    /// Every state, for previews and tests.
    public static let all: [SecureInstallState] = [.notReporting, .checking, .verified] + SecureInstallIssue.allCases
        .map { .needsAttention($0) }
}
