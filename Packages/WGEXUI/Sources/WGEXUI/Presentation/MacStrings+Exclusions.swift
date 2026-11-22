// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// M08-T03 seam: tunnel exclusions (DEC-087) on the Mac tunnel page and in the Edit sheet.
public nonisolated extension MacStrings {
    /// Tunnel page row label and Edit sheet section title.
    static let exclusions = "Exclusions"
    /// Tunnel page value when the tunnel has no exclusions.
    static let exclusionsNone = "None"
    /// The one-line note under the Edit sheet's Exclusions section.
    static let exclusionsNote = "Traffic to these addresses and names skips the tunnel and the kill switch."
    /// Placeholder of the field that adds an exclusion.
    static let exclusionPlaceholder = "Address, range or host name"
    /// Button that adds the typed exclusion.
    static let addExclusion = "Add"
    /// Button that removes one exclusion.
    static let removeExclusion = "Remove"
    /// Inline problem when the typed entry is already in the list.
    static let exclusionAlreadyListed = "This exclusion is already in the list."

    /// Tunnel page value: the number of exclusions.
    static func exclusionCount(_ count: Int) -> String {
        count == 1 ? "1 exclusion" : "\(count) exclusions"
    }

    /// Accessibility label of one exclusion's Remove button.
    static func removeExclusionNamed(_ entry: String) -> String {
        "Remove \(entry)"
    }

    /// Warning line on the tunnel page for host names the last resolution could not look up (the core's words).
    static func exclusionsUnresolved(_ names: [String]) -> String {
        UserStrings.exclusionUnresolved(names)
    }
}
