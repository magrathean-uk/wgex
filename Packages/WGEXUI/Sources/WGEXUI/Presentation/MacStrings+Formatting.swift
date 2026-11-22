// SPDX-License-Identifier: MIT

import Foundation

/// Byte units, elapsed-time units and reusable display formatting.
public nonisolated extension MacStrings {
    /// Copy used in Mac Settings and elapsed-time and byte formatting.
    static let text1Minute = "1 minute"
    /// Distinguishes an imported profile from an existing name.
    static func profileNameWithSuffix(_ name: String, _ suffix: String) -> String {
        "\(name) \(suffix)"
    }

    /// Decimal byte unit symbol.
    static let b = "B"
    /// Decimal megabyte unit symbol.
    static let mB = "MB"
    /// Decimal gigabyte unit symbol.
    static let gB = "GB"
    /// Decimal terabyte unit symbol.
    static let tB = "TB"
    /// Formats a number of elapsed seconds using the compact unit.
    static func s(_ seconds: String) -> String {
        "\(seconds) s"
    }

    /// Formats elapsed minutes using the compact unit.
    static func min(_ minutes: String) -> String {
        "\(minutes) min"
    }

    /// Formats elapsed hours using the compact unit.
    static func h(_ hours: String) -> String {
        "\(hours) h"
    }

    /// Formats elapsed days using the compact unit.
    static func d(_ days: String) -> String {
        "\(days) d"
    }

    /// Copy used in elapsed-time and byte formatting.
    static let ago = " ago"
    /// Formats the plural spoken minute count.
    static func minutes(_ count: String) -> String {
        "\(count) minutes"
    }

    /// Copy used in elapsed-time and byte formatting.
    static let text1Second = "1 second"
    /// Formats the plural spoken second count.
    static func seconds(_ count: String) -> String {
        "\(count) seconds"
    }

    /// Joins spoken minute and second parts with a space.
    static func durationParts(_ minutes: String, _ seconds: String) -> String {
        "\(minutes) \(seconds)"
    }

    /// Joins a formatted byte amount and its decimal unit.
    static func amountWithUnit(_ amount: String, _ unit: String) -> String {
        "\(amount) \(unit)"
    }
}
