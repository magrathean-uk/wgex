// SPDX-License-Identifier: MIT

/// Deduplicates app-wide announcements independently of view and sampling lifetimes.
public nonisolated struct AccessibilityAnnouncementState {
    private var verdict: ProtectionVerdict?
    private var toast: String?

    /// Starts with no previously displayed state.
    public init() {}

    /// One atomic state announcement per verdict edge, and one per new toast.
    /// Age, countdown and traffic updates never announce on their own.
    public mutating func messages(presentation: ProtectionPresentation, toast: String?) -> [String] {
        var messages: [String] = []
        if let verdict, verdict != presentation.verdict {
            messages.append(presentation.accessibilityLabel)
        }
        if let toast, toast != self.toast {
            messages.append(toast)
        }
        verdict = presentation.verdict
        self.toast = toast
        return messages
    }
}
