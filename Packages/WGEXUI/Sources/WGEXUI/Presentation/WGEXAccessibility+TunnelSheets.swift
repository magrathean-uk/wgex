// SPDX-License-Identifier: MIT

/// M07-T04 seam: identifiers of the Add, Review, Edit, Export, Delete and empty-window screens.
/// A `requiredAtLaunch` change is a retire plus a re-add.
public nonisolated extension WGEXAccessibility {
    /// Identifiers M07-T04 adds to ``catalogue``.
    static let tunnelSheetsEntries: [Entry] = [
        // Add a Tunnel (SPEC 6.1): the third row, shown whenever the sheet opens.
        Entry(screen: .importReview, id: "wgex.importReview.createEmpty", requiredAtLaunch: true),
        // Review Tunnel (SPEC 6.2): plain-word problems, and the several-files list with Add All.
        Entry(screen: .importReview, id: "wgex.importReview.problems", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.item", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.addAll", requiredAtLaunch: false),
        // M07-T09 (DEC-110 item 21): the list's tick and server per row; the Add All button reads "Add <count>" when some are
        // unticked and keeps its identifier.
        Entry(screen: .importReview, id: "wgex.importReview.itemTick", requiredAtLaunch: false),
        Entry(screen: .importReview, id: "wgex.importReview.itemEndpoint", requiredAtLaunch: false),
        // Edit sheet (SPEC 6.3): click-to-reveal keys, Edit as Text and the problem list.
        Entry(screen: .editor, id: "wgex.editor.privateKey", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.presharedKey", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.editAsText", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.editAsForm", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.configurationText", requiredAtLaunch: false),
        Entry(screen: .editor, id: "wgex.editor.problems", requiredAtLaunch: false),
        // Empty window (SPEC 6.5).
        Entry(screen: .main, id: "wgex.main.dropHint", requiredAtLaunch: false),
    ]

    /// Base identifiers M07-T04 removes from ``catalogue``: the QR import (D8), the old drop box (the whole window takes
    /// drops), Skip File (Cancel and the several-files list replace it) and the review's DNS row (not in SPEC 6.2).
    static let tunnelSheetsRetired: Set<String> = [
        "wgex.importReview.qrFromImage",
        "wgex.importReview.dropTarget",
        "wgex.importReview.skipFile",
        "wgex.importReview.dns",
    ]
}
