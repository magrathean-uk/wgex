// SPDX-License-Identifier: MIT

/// M08-T03 seam: identifiers of the exclusions controls (DEC-087). The tunnel page row keeps `wgex.main.detail` with the
/// item `exclusions`; its sheet's rows use `wgex.main.exclusion`.
public nonisolated extension WGEXAccessibility {
    /// Identifiers M08-T03 adds to ``catalogue``.
    static let exclusionsEntries: [Entry] = [
        // Tunnel page: the unresolved host names warning (live) and the list sheet's rows.
        Entry(screen: .main, id: "wgex.main.exclusionWarning", requiredAtLaunch: false),
        Entry(screen: .main, id: "wgex.main.exclusion", requiredAtLaunch: false),
        // Edit sheet: the list, the add field and its inline problem, Add and Remove.
        Entry(screen: .editor, id: "wgex.editor.exclusion", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.exclusionInput", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.exclusionProblem", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.addExclusion", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.removeExclusion", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.exclusionsNote", requiredAtLaunch: false),
    ]
}
