// SPDX-License-Identifier: MIT

import Foundation

/// Configuration sources, profile review, duplicates and import outcomes.
public nonisolated extension MacStrings {
    /// Copy used in Mac import review.
    static let paste = "Paste"
    /// Copy used in Mac import review and the shared profile editor string facade.
    static let importLabel = "Import"
    /// Copy used in Mac import review.
    static let routes = "Routes"
    /// Copy used in Mac import review.
    static let aMatchingProfileAlreadyExists = "A matching tunnel already exists"
    /// Copy used in Mac import review.
    static let duplicate = "Duplicate"
    /// Copy used in Mac import review.
    static let keepBoth = "Keep both"
    /// Copy used in Mac import review.
    static let replace = "Replace"
    /// Copy used in Mac import review.
    static let usingTheSamePrivateKeyOnTwo = "Using the same private key on two devices can interrupt both connections."
    /// Copy used in Mac import review.
    static let importCouldNotBeCompletedTry = "Import could not be completed. Try again."
    /// Copy used in the menu extra and main window.
    static let importFromFile = "Import from File…"
    /// Copy used in the shared profile editor string facade.
    static let theProfileCouldNotBeImported = "The tunnel could not be imported. Try again."
    /// Navigation title of the shared profile review form.
    static let reviewImportTitle = "Review import"
    /// Shared profile review action that imports and then connects.
    static let importAndConnectAction = "Add and Activate"
    /// Copy used in the shared profile editor string facade.
    static let duplicateProfiles = "Duplicate tunnels"
    /// Copy used in the shared profile editor string facade.
    static let aProfileWithThisNameAlready = "A tunnel with this name already exists. Edit the name to distinguish them."
    /// Copy used in the shared profile editor string facade.
    static let thisPublicKeyIsAlready = "This public key is already installed. Activating both tunnels may interrupt either one."
    /// Copy used in the shared profile editor string facade.
    static let postUpHooksAreNotSupportedAnd = "PostUp hooks are not supported and were removed. Commands in this configuration will not run."
    /// Copy used in the shared profile editor string facade.
    static let theConfigurationIsNotValidUTF8 = "The configuration is not valid UTF-8 text. Save it as UTF-8 before importing."
    /// Copy used in the shared profile editor string facade.
    static let importUnavailableUntilErrors = "Import unavailable until errors are fixed."
}
