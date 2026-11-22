// SPDX-License-Identifier: MIT

import Foundation

/// A daemon log line after redaction.
public struct RedactedLogLine: Codable, Sendable, Hashable {
    /// Time of the line.
    public var date: Date
    /// Log category.
    public var category: String
    /// Redacted message.
    public var message: String
    /// Profile the line belongs to, if any.
    public var profileID: UUID?

    /// Creates a line.
    public init(date: Date, category: String, message: String, profileID: UUID?) {
        self.date = date
        self.category = category
        self.message = message
        self.profileID = profileID
    }
}
