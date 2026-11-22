// SPDX-License-Identifier: MIT

import Foundation

/// A redacted diagnostics archive (stored zip) produced by the daemon.
public struct DiagnosticsBundle: Codable, Sendable, Hashable {
    /// Creation time.
    public var createdAt: Date
    /// Archive bytes.
    public var archive: Data

    /// Creates a bundle.
    public init(createdAt: Date, archive: Data) {
        self.createdAt = createdAt
        self.archive = archive
    }
}
