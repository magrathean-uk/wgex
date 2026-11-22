// SPDX-License-Identifier: MIT

import WGEXCore

/// A profile as registered with the daemon; secrets references are
/// `.daemonStore` only (02 §5).
public struct DaemonProfile: Codable, Sendable, Hashable {
    /// The profile.
    public var profile: TunnelProfile
    /// Daemon-allocated revision in accepted registrations. Legacy installs treat it as a CAS proposal.
    public var revision: UInt64

    /// Creates a registration.
    public init(profile: TunnelProfile, revision: UInt64) {
        self.profile = profile
        self.revision = revision
    }
}
