// SPDX-License-Identifier: MIT

import Foundation

/// What a diagnostics bundle should contain; filtered to the caller's profiles.
public struct DiagnosticsRequest: Codable, Sendable, Hashable {
    /// Include redacted log lines.
    public var includeLogs: Bool
    /// Earliest log time, if any.
    public var since: Date?
    /// Profiles to include; empty means every profile the caller owns.
    public var profileIDs: [UUID]

    /// Creates a request.
    public init(includeLogs: Bool, since: Date?, profileIDs: [UUID]) {
        self.includeLogs = includeLogs
        self.since = since
        self.profileIDs = profileIDs
    }
}
