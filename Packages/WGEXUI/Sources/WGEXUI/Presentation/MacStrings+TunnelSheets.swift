// SPDX-License-Identifier: MIT

import Foundation

/// SPEC 6.1 to 6.5: the Add a Tunnel, Review Tunnel and Edit sheets, Delete Tunnel and the empty window (M07-T04).
public nonisolated extension MacStrings {
    /// Title of the Add a Tunnel sheet (SPEC 6.1).
    static let addATunnelTitle = "Add a Tunnel"
    /// What the Add a Tunnel sheet is for, including the window-wide drop target.
    static let addATunnelMessage = "Use a WireGuard configuration made for this Mac. You can also drop a file anywhere on this window."
    /// Add a Tunnel row and empty-window button that read a configuration from the clipboard.
    static let pasteFromClipboard = "Paste from Clipboard"
    /// Add a Tunnel row and menu command that open the editor on a new tunnel with a fresh key pair.
    static let createEmptyTunnel = "Create Empty Tunnel"
    /// One-line answer when the clipboard holds no WireGuard configuration.
    static let clipboardHoldsNoConfiguration = "The clipboard does not hold a WireGuard configuration."
    /// Title of the review sheet for one imported configuration (SPEC 6.2).
    static let reviewTunnelTitle = "Review Tunnel"
    /// Title of the review sheet for several imported configurations.
    static let reviewTunnelsTitle = "Review Tunnels"
    /// Review row and edit group heading for the peer.
    static let server = "Server"
    // The Review row "Tunnel address" and the Edit row "Keepalive" use the tunnel page's declarations
    // (`MacStrings+TunnelPage.swift`): one word, one declaration.
    /// Review button that saves and then activates the tunnel (SPEC 3 says Activate, not Connect).
    static let addAndActivate = "Add and Activate"
    /// Review button that saves every configuration without errors.
    static let addAll = "Add All"
    /// Second line of a review list row without problems.
    static let readyToAdd = "Ready to add"
    /// Heading of the duplicate choice in the review sheet.
    static let matchingTunnelExists = "A tunnel with this name or key already exists"
    /// Explains the duplicate choice.
    static let keepBothOrReplaceTunnel = "Keeping both adds this one under a new name. Replacing updates the saved tunnel."
    /// Plain-word problem for removed PreUp, PostUp, PreDown and PostDown commands.
    static let commandsWereRemoved = "Commands such as PostUp are not supported and were removed."
    /// Plain-word problem for a setting the Mac cannot apply.
    static let settingWasRemoved = "A setting that does not apply on the Mac was removed."
    /// Plain-word problem when two servers share a public key.
    static let serversShareAKey = "Two servers have the same public key. Remove one of them."
    /// Plain-word problem when another tunnel already uses this key.
    static let keyUsedByAnotherTunnel = "Another tunnel uses this key. Using one key twice can interrupt both tunnels."
    /// Plain-word problem for a tunnel saved without an address; it blocks activation, not saving (DEC-088).
    static let addAnAddressBeforeActivating = "Add an address before activating this tunnel."
    /// Plain-word problem for a tunnel saved without a server; it blocks activation, not saving (DEC-088).
    static let addAServerBeforeActivating = "Add a server before activating this tunnel."
    /// Why an incomplete tunnel cannot be activated; shown on the tunnel page and for the menu and login start.
    static let activationNeedsAddressAndServer = "Add an address and a server before activating this tunnel."
    /// A tunnel that must be complete (an import, or a saved complete tunnel) lacks an address.
    static let needsAnAddress = "This tunnel needs at least one address."
    /// A tunnel that must be complete (an import, or a saved complete tunnel) lacks a server.
    static let needsAServer = "This tunnel needs at least one server."
    /// The name check (1 to 128 characters) in plain words.
    static let typeATunnelName = "Type a name for this tunnel."
    /// On-demand and start-up need a tunnel that can be activated.
    static let incompleteTunnelOptions = "Add an address and a server before choosing on-demand or start-up options."
    /// Edit sheet title for a tunnel that has not been saved yet.
    static let newTunnelTitle = "New Tunnel"
    /// Edit sheet button that adds a server group.
    static let addServer = "Add Server"
    /// Edit sheet button that removes one server group.
    static let removeServer = "Remove Server"
    /// Edit sheet button that swaps the form for the WireGuard file.
    static let editAsText = "Edit as Text"
    /// Edit sheet button that returns from the WireGuard file to the form.
    static let editAsForm = "Edit as Form"
    /// Edit group for listen port, MTU and search domains.
    static let advanced = "Advanced"
    /// Edit group for the start-up choices.
    static let startUp = "Start-up"
    /// Edit button that replaces the key pair.
    static let generateKeyPair = "Generate Key Pair"
    /// Confirmation before a new key pair replaces an existing one.
    static let newKeyPairWarning = "A new key pair changes this Mac's public key. Update the server before activating."
    /// Confirmation before unsaved edits are dropped.
    static let tunnelChangesWillBeLost = "Your changes to this tunnel will be lost."
    /// Button that drops unsaved edits.
    static let discardChangesAction = "Discard Changes"
    /// Button that returns to the edit sheet.
    static let keepEditingAction = "Keep Editing"
    /// Accessibility action that reveals the private key.
    static let show = "Show"
    /// Value of the preshared key row when the server has none.
    static let noPresharedKey = "None"
    /// Lead line when Edit as Text holds text that is not a WireGuard configuration.
    static let textIsNotAConfiguration = "This text is not a WireGuard configuration that WGEX can use."
    /// Edit as Text had to close (the app or window went away) with text that does not parse; the text was dropped.
    static let textChangesDiscarded = "Your text changes could not be applied and were discarded."
    /// Tooltip and accessibility hint of a revealed key.
    static let keyRowHelp = "Click to hide. Paste a key to replace it."
    /// A paste into a revealed key row that is not a WireGuard key; nothing changed.
    static let clipboardHoldsNoKey = "The clipboard does not hold a WireGuard key."
    /// Second line of the delete alert.
    static let deleteCannotBeUndone = "This cannot be undone."
    /// Destructive button of the delete alert.
    static let deleteAction = "Delete"
    /// Empty window message (SPEC 6.5).
    static let addAConfigurationMadeForThisMac = "Add a WireGuard configuration made for this Mac."
    /// Small line under the empty window's buttons.
    static let orDropAConfFileHere = "or drop a .conf file here"

    /// Edit sheet title for a saved tunnel.
    static func editTunnelTitle(_ name: String) -> String {
        "Edit \(name)"
    }

    /// Delete alert title.
    static func deleteTunnelTitle(_ name: String) -> String {
        "Delete \(name)?"
    }

    /// Delete alert line for the active tunnel.
    static func tunnelWillBeDeactivatedFirst(_ name: String) -> String {
        "\(name) is active. It will be deactivated first."
    }

    /// A delete that could not deactivate the tunnel first; `reason` is the resolved error copy, if any.
    static func tunnelNotDeletedNotDeactivated(_ name: String, reason: String?) -> String {
        let lead = "\(name) could not be deactivated, so it was not deleted."
        return reason.map { lead + " " + $0 } ?? lead
    }

    /// Review list button when some tunnels are unticked: "Add 2".
    static func addCount(_ count: Int) -> String {
        "Add \(count)"
    }

    /// Names the review items Add All leaves out.
    static func leftOutWithErrors(_ names: String) -> String {
        "Not added because of errors: \(names)."
    }
}
