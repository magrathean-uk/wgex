// SPDX-License-Identifier: MIT

import Foundation

/// Spoken summaries and state qualifiers.
public nonisolated extension MacStrings {
    /// Names the active transport in the orb summary.
    static func transportAnnouncement(_ transport: String) -> String {
        "Transport: \(transport)"
    }

    /// Introduces the measured peer health description.
    static func health(_ description: String) -> String {
        "Health: \(description)"
    }

    /// Combines the verdict, evidence and optional health into one announcement.
    static func protectionAnnouncement(_ verdict: String, _ evidence: String, _ health: String) -> String {
        "\(verdict). \(evidence)\(health)"
    }

    /// Introduces the outcome in a protection chip.
    static func protectionAnnouncementLabel(_ outcome: String) -> String {
        "Protection: \(outcome)"
    }

    /// Combines profile name, state and endpoint for VoiceOver.
    static func profileAnnouncement(_ name: String, _ state: String, _ endpoint: String) -> String {
        "\(name), \(state), \(endpoint)"
    }

    /// Describes a direction without measured chart data.
    static func last30SecondsNoData(_ direction: String) -> String {
        "\(direction), last 30 seconds, no data"
    }

    /// Reads the peak rate for one traffic direction.
    static func last30SecondsPeak(_ direction: String, _ rate: String) -> String {
        "\(direction), last 30 seconds, peak \(rate)"
    }

    /// Combines a warning title with its consequence.
    static func warningAnnouncement(_ title: String, _ consequence: String) -> String {
        "\(title). \(consequence)"
    }

    /// Speaks the current setup step and total step count.
    static func stepOf(_ step: String, _ total: String) -> String {
        "Step \(step) of \(total)"
    }

    /// Speaks a named field and its current value.
    static func namedValue(_ name: String, _ value: String) -> String {
        "\(name): \(value)"
    }

    /// Introduces an inline validation warning.
    static func warning(_ message: String) -> String {
        "Warning: \(message)"
    }

    /// Combines a statistic name with its measured value.
    static func statAnnouncement(_ name: String, _ value: String) -> String {
        "\(name), \(value)"
    }

    /// Spoken suffix qualifying a statistic as last-known data.
    static let staleQualifier = ", stale"
    /// Introduces the captive-window warning to VoiceOver.
    static let captiveAnnouncementPrefix = "Sign-in window. "
    /// Reads an event timestamp and its description; never contains key material.
    static func eventAnnouncement(_ time: String, _ description: String) -> String {
        "\(time), \(description)"
    }

    /// Copy used in the connection orb.
    static let connectionStatus = "Tunnel status: "
    /// Speaks a field name followed by its validation state.
    static func fieldValidation(_ field: String, _ validation: String) -> String {
        "\(field), \(validation)"
    }

    /// Reads the route summary and validation state.
    static func allowedIPsAnnouncement(_ summary: String, _ validation: String) -> String {
        "Allowed IPs, \(summary), \(validation)"
    }

    /// Describes a masked key field without exposing its contents.
    static func hidden(_ field: String) -> String {
        "\(field), hidden"
    }

    /// Describes a key field after the reveal-once action.
    static func revealed(_ field: String) -> String {
        "\(field), revealed"
    }

    /// Explains that a key field has used its single reveal.
    static func hiddenAlreadyRevealedOnce(_ field: String) -> String {
        "\(field), hidden, already revealed once"
    }
}
