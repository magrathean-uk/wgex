// SPDX-License-Identifier: MIT

import Foundation

/// A log line from the engine. The engine filters secrets before emitting.
public struct EngineLogLine: Sendable, Hashable {
    /// Severity.
    public enum Level: Int32, Sendable, Hashable {
        /// Verbose.
        case debug = 0
        /// Informational.
        case info = 1
        /// Error.
        case error = 2
    }

    /// Severity.
    public var level: Level
    /// Message text.
    public var message: String
    /// Receive time.
    public var date: Date

    /// Creates a line.
    public init(level: Level, message: String, date: Date) {
        self.level = level
        self.message = message
        self.date = date
    }
}
