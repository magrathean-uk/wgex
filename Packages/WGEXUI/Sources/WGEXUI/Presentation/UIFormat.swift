// SPDX-License-Identifier: MIT

import Foundation

/// Deterministic formatting for rates, sizes, ages and countdowns. The
/// string catalogue and locale-aware formats arrive with localisation.
public nonisolated enum UIFormat {
    private static let units = [MacStrings.b, "kB", MacStrings.mB, MacStrings.gB, MacStrings.tB]

    /// "0 B/s", "999 B/s", "1.5 kB/s", "12 kB/s", "1.2 MB/s"; "Unavailable"
    /// for a negative or non-finite rate (never shown as zero).
    public static func rate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return MacStrings.unavailable }
        return scaled(bytesPerSecond) + "/s"
    }

    /// "0 B", "1.5 kB", "12 MB" (decimal units).
    public static func bytes(_ count: UInt64) -> String {
        scaled(Double(count))
    }

    /// "0 s", "18 s", "3 min", "2 h", "4 d"; negative ages count as zero.
    public static func age(_ date: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(date)))
        switch seconds {
        case ..<60: return MacStrings.s(String(seconds))
        case ..<3600: return MacStrings.min(String(seconds / 60))
        case ..<86400: return MacStrings.h(String(seconds / 3600))
        default: return MacStrings.d(String(seconds / 86400))
        }
    }

    /// "18 s ago".
    public static func ago(_ date: Date, now: Date) -> String {
        age(date, now: now) + MacStrings.ago
    }

    /// "4:32", "0:05", "1:02:03"; rounds up so the last second shows "0:01",
    /// and anything at or past zero shows "0:00".
    public static func countdown(_ remaining: TimeInterval) -> String {
        let total = remaining.isFinite ? max(0, Int(remaining.rounded(.up))) : 0
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        let paddedSeconds = seconds < 10 ? "0\(seconds)" : "\(seconds)"
        if hours > 0 {
            let paddedMinutes = minutes < 10 ? "0\(minutes)" : "\(minutes)"
            return "\(hours):\(paddedMinutes):\(paddedSeconds)"
        }
        return "\(minutes):\(paddedSeconds)"
    }

    /// "4 minutes 32 seconds", "1 minute", "1 second" for VoiceOver.
    public static func spokenDuration(_ remaining: TimeInterval) -> String {
        let total = remaining.isFinite ? max(0, Int(remaining.rounded(.up))) : 0
        let minutes = total / 60
        let seconds = total % 60
        let minuteText = minutes == 1 ? MacStrings.text1Minute : MacStrings.minutes(String(minutes))
        let secondText = seconds == 1 ? MacStrings.text1Second : MacStrings.seconds(String(seconds))
        if minutes == 0 {
            return secondText
        }
        return seconds == 0 ? minuteText : MacStrings.durationParts(String(minuteText), String(secondText))
    }

    private static func scaled(_ value: Double) -> String {
        var amount = value
        var unit = 0
        while unit < units.count - 1, roundedForDisplay(amount) >= 1000 {
            amount /= 1000
            unit += 1
        }
        let text = if unit == 0 {
            String(Int(amount.rounded()))
        } else if roundedForDisplay(amount) < 10 {
            String(format: "%.1f", (amount * 10).rounded() / 10)
        } else {
            String(Int(amount.rounded()))
        }
        return MacStrings.amountWithUnit(String(text), String(units[unit]))
    }

    private static func roundedForDisplay(_ amount: Double) -> Double {
        amount < 9.95 ? (amount * 10).rounded() / 10 : amount.rounded()
    }
}

/// Copy for the Mac captive window (plan 06 §4.1).
public nonisolated enum CaptiveWindowCopy {
    /// "Unprotected for 4:32 to sign in to this network", or the ended line.
    public static func message(remaining: TimeInterval) -> String {
        remaining > 0
            ? MacStrings.captiveWindowDuration(String(UIFormat.countdown(remaining)))
            : MacStrings.captiveWindowEndedRestoring
    }

    /// Spoken form of ``message(remaining:)``.
    public static func spokenMessage(remaining: TimeInterval) -> String {
        remaining > 0
            ? MacStrings.captiveWindowDuration(String(UIFormat.spokenDuration(remaining)))
            : MacStrings.captiveWindowEndedRestoring
    }
}
