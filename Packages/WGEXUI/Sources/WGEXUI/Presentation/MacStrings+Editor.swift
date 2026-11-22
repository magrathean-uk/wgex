// SPDX-License-Identifier: MIT

import Foundation

/// WireGuard fields, peer editing, key controls and validation feedback.
public nonisolated extension MacStrings {
    /// Copy used in Mac import review and Mac Settings.
    static let dns = "DNS"
    /// Copy used in the Mac details grid and Mac Settings.
    static let mtu = "MTU"
    /// Copy used in Mac import review and the shared profile editor string facade.
    static let name = "Name"
    /// Copy used in the Mac details grid and Mac import review.
    static let addresses = "Addresses"
    /// Copy used in address and route validation controls and the Mac details grid.
    static let endpoint = "Endpoint"
    /// Copy used in the Mac details grid and the shared profile editor string facade.
    static let interface = "Interface"
    /// Copy used in the Mac details grid and the shared profile editor string facade.
    static let listenPort = "Listen port"
    /// Copy used in address and route validation controls and the Mac details grid.
    static let allowedIPs = "Allowed IPs"
    /// Copy used in the Mac details grid and the shared profile editor string facade.
    static let publicKey = "Public key"
    /// Copy used in the shared profile editor string facade.
    static let profileEditor = "Tunnel editor"
    /// Copy used in the automation identifier helpers and the shared profile editor string facade.
    static let privateKey = "Private key"
    /// Copy used in the automation identifier helpers and the shared profile editor string facade.
    static let presharedKey = "Preshared key"
    /// Copy used in the shared profile editor string facade.
    static let searchDomains = "Search domains"
    /// Copy used in the shared profile editor string facade.
    static let peers = "Peers"
    /// Copy used in the shared profile editor string facade.
    static let persistentKeepaliveSeconds = "Persistent keepalive (seconds)"
    /// Copy used in the shared profile editor string facade.
    static let keepaliveValidation = "Keepalive must be 0 to 65535 seconds; 0 turns it off."
    /// Copy used in the shared profile editor string facade.
    static let ipv6Policy = "IPv6 policy"
    /// Copy used in the shared profile editor string facade.
    static let tunnelIPv6 = "Tunnel IPv6"
    /// Copy used in the shared profile editor string facade.
    static let blockIPv6OutsideTheTunnel = "Block IPv6 outside the tunnel"
    /// Copy used in the shared profile editor string facade.
    static let allowIPv6OutsideTheTunnel = "Allow IPv6 outside the tunnel"
    /// Consequence of allowing IPv6 alongside an IPv4-only imported tunnel.
    static let ipv6OutsideTunnelConsequence = "IPv6 traffic can leave outside the tunnel. This traffic is not protected."
    /// Copy used in the shared profile editor string facade.
    static let dnsPolicy = "DNS policy"
    /// Copy used in the shared profile editor string facade.
    static let allDNSThroughTheTunnel = "All DNS through the tunnel"
    /// Copy used in the shared profile editor string facade.
    static let splitDNS = "Split DNS"
    /// Copy used in the shared profile editor string facade.
    static let systemDNS = "System DNS"
    /// Copy used in the shared profile editor string facade.
    static let dnsMatchDomains = "DNS match domains"
    /// Copy used in the shared profile editor string facade.
    static let macOSOptions = "macOS options"
    /// Copy used in the shared profile editor string facade.
    static let save = "Save"
    /// Copy used in the shared profile editor string facade.
    static let discardChanges = "Discard changes"
    /// Copy used in the shared profile editor string facade.
    static let yourUnsavedProfileChangesWill = "Your unsaved tunnel changes will be lost."
    /// Copy used in the shared profile editor string facade.
    static let keepEditing = "Keep editing"
    /// Copy used in the shared profile editor string facade.
    static let generateKeypair = "Generate keypair"
    /// Copy used in the shared profile editor string facade.
    static let replacingThisKeyChangesThe = "Replacing this key changes the public key. Update the server before activating the tunnel."
    /// Copy used in the shared profile editor string facade.
    static let addPeer = "Add peer"
    /// Copy used in the shared profile editor string facade.
    static let removePeer = "Remove peer"
    /// Copy used in the shared profile editor string facade.
    static let movePeerUp = "Move peer up"
    /// Copy used in the shared profile editor string facade.
    static let movePeerDown = "Move peer down"
    /// Copy used in the shared profile editor string facade.
    static let excludePrivateNetworksRemovesR = "Exclude private networks removes RFC 1918 and IPv4 link-local routes. IPv6 routes stay in the tunnel."
    /// Copy used in the shared profile editor string facade.
    static let errors = "Errors"
    /// Copy used in the shared profile editor string facade.
    static let warnings = "Warnings"
    /// Copy used in the shared profile editor string facade.
    static let theProfileCouldNotBeSavedCheck = "The tunnel could not be saved. Check that its keys are available and try again."
    /// Copy used in the shared profile editor string facade.
    static let aKeypairCouldNotBeGeneratedTry = "A keypair could not be generated. Try again."
    /// Names the source line for an import diagnostic.
    static func line(_ number: String) -> String {
        "Line \(number)"
    }

    /// Copy used in the shared profile editor string facade.
    static let saveUnavailableUntilErrorsAre = "Save unavailable until errors are fixed."
    /// Copy used in the shared profile editor string facade.
    static let updateKey = "Update key"
    /// Copy used in the shared profile editor string facade.
    static let newKeyBase64 = "New key (base64)"
    /// Copy used in the shared profile editor string facade.
    static let removePresharedKey = "Remove preshared key"
    /// Copy used in the shared profile editor string facade.
    static let valid = "Valid"
    /// Names an editor peer by its position.
    static func peer(_ number: String) -> String {
        "Peer \(number)"
    }

    /// Copy used in address and route validation controls.
    static let address = "Address"
    /// Copy used in address and route validation controls and the automation identifier helpers.
    static let allowedIP = "Allowed IP"
    /// Copy used in address and route validation controls.
    static let remove = "Remove"
    /// Copy used in address and route validation controls and the Allowed IPs editor summary.
    static let allTraffic = "All traffic"
    /// Copy used in address and route validation controls.
    static let excludePrivateNetworks = "Exclude private networks"
    /// Copy used in address and route validation controls.
    static let add = "Add"
    /// Copy used in masked-key editing controls.
    static let copy = "Copy"
    /// Copy used in masked-key editing controls.
    static let hide = "Hide"
    /// Copy used in masked-key editing controls.
    static let revealOnce = "Reveal once"
    /// Copy used in masked-key editing controls.
    static let revealedOnceOpenTheEditorAgain = "Revealed once. Open the editor again to reveal it"
    /// Copy used in the Allowed IPs editor summary.
    static let allTrafficExceptPrivateNetworks = "All traffic except private networks"
    /// Copy used in the Allowed IPs editor summary.
    static let allIPv4TrafficExceptPrivate = "All IPv4 traffic except private networks"
    /// Copy used in the Allowed IPs editor summary.
    static let singleRange = "1 range"
    /// Formats a plural count of allowed address ranges.
    static func ranges(_ count: String) -> String {
        "\(count) ranges"
    }

    /// Copy used in the menu bar allowed-networks line when a profile has no allowed networks.
    static let none = "none"
    /// Formats the menu bar allowed-networks line.
    static func allowedNetworksLine(_ networks: String) -> String {
        "Allowed networks: \(networks)"
    }
}
