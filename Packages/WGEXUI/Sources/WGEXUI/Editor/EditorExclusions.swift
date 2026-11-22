// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Tunnel exclusions in the editor (DEC-087, M08-T03): one entry per line, added through the core's parser and validated with
/// the core's messages, so any entry form the core accepts (ports from M08-T02 included) is accepted here.
public extension ProfileEditorModel {
    /// Inline validation of a typed exclusion before Add: the core's parser, then the core's tunnel checks on the draft with
    /// the entry added (a default route, the 64-entry limit, the tunnel's own address, DNS server or endpoint).
    func exclusionValidation(_ text: String) -> FieldValidation {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return .empty }
        guard let entry = try? TunnelExclusions.entry(trimmed) else { return .invalid(UserStrings.exclusionHostName) }
        let current = candidateProfile
        if current.exclusions.entries.contains(entry) {
            return .invalid(MacStrings.exclusionAlreadyListed)
        }
        var trial = current
        trial.exclusions.append(entry)
        let before = Set(current.validate(publicKeysInUse: publicKeysInUse).map(\.message))
        let added = trial.validate(publicKeysInUse: publicKeysInUse).first {
            Self.exclusionMessages.contains($0.message) && !before.contains($0.message)
        }
        return added.map { .invalid($0.message) } ?? .valid
    }

    /// Adds a typed exclusion in the core's canonical spelling when it passes ``exclusionValidation(_:)``.
    @discardableResult
    func addExclusion(_ text: String) -> Bool {
        guard exclusionValidation(text) == .valid,
              let entry = try? TunnelExclusions.entry(text.trimmingCharacters(in: .whitespaces)) else { return false }
        draft.exclusions.append(entry.text)
        return true
    }

    /// Removes one listed exclusion.
    func removeExclusion(_ text: String) {
        draft.exclusions.removeAll { $0 == text }
    }
}

package extension ProfileEditorModel {
    /// The core's exclusion messages; a validation issue carrying one belongs to the Exclusions section.
    static let exclusionMessages: Set<String> = [
        UserStrings.exclusionLimit, UserStrings.exclusionDefaultRoute, UserStrings.exclusionHostName,
        UserStrings.exclusionOverlapsTunnel,
    ]

    /// The draft's entry texts as the core value; a line that does not parse is left out (it is listed as a field problem).
    static func exclusions(_ texts: [String]) -> TunnelExclusions {
        var result = TunnelExclusions()
        for text in texts {
            if let entry = try? TunnelExclusions.entry(text) {
                result.append(entry)
            }
        }
        return result
    }
}
