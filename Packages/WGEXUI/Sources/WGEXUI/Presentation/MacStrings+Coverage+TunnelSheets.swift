// SPDX-License-Identifier: MIT

/// M07-T04 seam: every new string of the Add, Review, Edit, Export, Delete and empty-window screens.
public nonisolated extension MacStrings {
    /// Static copy added by M07-T04, appended to ``catalogue``.
    static let tunnelSheetsCatalogue: [String] = [
        addATunnelTitle, addATunnelMessage, pasteFromClipboard, createEmptyTunnel, clipboardHoldsNoConfiguration,
        reviewTunnelTitle, reviewTunnelsTitle, server, addAndActivate, addAll, readyToAdd, matchingTunnelExists,
        keepBothOrReplaceTunnel, commandsWereRemoved, settingWasRemoved, serversShareAKey, keyUsedByAnotherTunnel,
        addAnAddressBeforeActivating, addAServerBeforeActivating, activationNeedsAddressAndServer, needsAnAddress, needsAServer,
        typeATunnelName, incompleteTunnelOptions, newTunnelTitle, addServer, removeServer, editAsText, editAsForm,
        advanced, startUp, generateKeyPair, newKeyPairWarning, tunnelChangesWillBeLost, discardChangesAction, keepEditingAction,
        show, noPresharedKey, textIsNotAConfiguration, deleteCannotBeUndone, deleteAction, addAConfigurationMadeForThisMac,
        orDropAConfFileHere, textChangesDiscarded, keyRowHelp, clipboardHoldsNoKey,
    ]
}
