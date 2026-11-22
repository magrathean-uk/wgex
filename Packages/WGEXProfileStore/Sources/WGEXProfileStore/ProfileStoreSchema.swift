// SPDX-License-Identifier: MIT

import WGEXCore

/// Versions of the documents the profile store writes (02 §10).
public enum ProfileStoreSchema {
    /// Version of `profiles/<uuid>.json`.
    public static let profileDocumentVersion = ProfileDocument.currentSchemaVersion
    /// Version of `journal.json`.
    public static let journalVersion = 1
}
