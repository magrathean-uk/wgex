// SPDX-License-Identifier: MIT

/// UK English copy for the shared editor, review and export flows.
public nonisolated enum EditorStrings {
    public static let title = MacStrings.profileEditor
    public static let interface = MacStrings.interface
    public static let name = MacStrings.name
    public static let privateKey = MacStrings.privateKey
    public static let publicKey = MacStrings.publicKey
    public static let presharedKey = MacStrings.presharedKey
    public static let addresses = MacStrings.addresses
    public static let listenPort = MacStrings.listenPort
    public static let mtu = MacStrings.mtu
    public static let dns = MacStrings.dns
    public static let searchDomains = MacStrings.searchDomains
    public static let peers = MacStrings.peers
    public static let endpoint = MacStrings.endpoint
    public static let keepalive = MacStrings.persistentKeepaliveSeconds
    public static let keepaliveLimit = MacStrings.keepaliveValidation
    public static let protection = MacStrings.protection
    public static let ipv6 = MacStrings.ipv6Policy
    public static let tunnelIPv6 = MacStrings.tunnelIPv6
    public static let blockIPv6 = MacStrings.blockIPv6OutsideTheTunnel
    public static let allowIPv6 = MacStrings.allowIPv6OutsideTheTunnel
    public static let dnsPolicy = MacStrings.dnsPolicy
    public static let tunnelDNS = MacStrings.allDNSThroughTheTunnel
    public static let splitDNS = MacStrings.splitDNS
    public static let systemDNS = MacStrings.systemDNS
    public static let splitDomains = MacStrings.dnsMatchDomains
    public static let allowLAN = MacStrings.allowLocalNetwork
    public static let forceAll = PlatformStrings.forceAllTraffic
    public static let forceWarning = [
        PlatformStrings.appUpdatesCanLeaveThisPhone,
        PlatformStrings.withLocalSharingAllowedCarPlay,
        PlatformStrings.withLocalSharingBlockedLocalDN,
        PlatformStrings.yourRealIPAddressMayBeExposed,
        PlatformStrings.phoneUpdateRecovery,
        PlatformStrings.thisIsARoutingPolicyNotAPromise,
    ]
    public static let cellular = PlatformStrings.excludeCellularServices
    public static let apns = PlatformStrings.excludeApplePushNotifications
    public static let communication = PlatformStrings.excludeDeviceCommunication
    public static let exclusions = PlatformStrings.excludedServicesCanSendTraffic
    public static let macOptions = MacStrings.macOSOptions
    public static let boot = MacStrings.startBeforeLogin
    public static let login = MacStrings.connectAtLogin
    public static let fileVault = MacStrings.theMacMustBeUnlockedBeforeThe
    public static let bootWarning = MacStrings.startingBeforeLoginRequires
    public static let transports = MacStrings.transports
    public static let udp = MacStrings.directWireGuardUDP
    public static let save = MacStrings.save
    public static let cancel = MacStrings.cancel
    public static let discard = MacStrings.discardChanges
    public static let discardWarning = MacStrings.yourUnsavedProfileChangesWill
    public static let continueEditing = MacStrings.keepEditing
    public static let generate = MacStrings.generateKeypair
    public static let generateWarning = MacStrings.replacingThisKeyChangesThe
    public static let addPeer = MacStrings.addPeer
    public static let removePeer = MacStrings.removePeer
    public static let moveUp = MacStrings.movePeerUp
    public static let moveDown = MacStrings.movePeerDown
    public static let privateRanges = MacStrings.excludePrivateNetworksRemovesR
    public static let errors = MacStrings.errors
    public static let warnings = MacStrings.warnings
    public static let diagnostics = MacStrings.diagnostics
    public static let generationFailed = MacStrings.aKeypairCouldNotBeGeneratedTry
    public static let importFailed = MacStrings.theProfileCouldNotBeImported
    public static func line(_ number: Int) -> String {
        MacStrings.line(String(number))
    }

    public static let saveBlocked = MacStrings.saveUnavailableUntilErrorsAre
    public static let review = MacStrings.reviewImportTitle
    public static let importProfile = MacStrings.importLabel
    public static let importConnect = MacStrings.importAndConnectAction
    public static let duplicates = MacStrings.duplicateProfiles
    public static let duplicateName = MacStrings.aProfileWithThisNameAlready
    public static let duplicateKey = MacStrings.thisPublicKeyIsAlready
    public static let hookWarning = MacStrings.postUpHooksAreNotSupportedAnd
    public static let invalidUTF8 = MacStrings.theConfigurationIsNotValidUTF8
    public static let importBlocked = MacStrings.importUnavailableUntilErrors
    public static let export = MacStrings.exportProfile
    public static let share = MacStrings.shareWithoutKeys
    public static let exportFile = MacStrings.exportConfigurationFile
    public static let confirmExport = MacStrings.exportPrivateKey
    public static let exportWarning = MacStrings.thisFileContainsThePrivateKey
    public static let confirm = MacStrings.exportFileWithKeys
    public static let qr = MacStrings.showQRCode
    public static let qrWarning = MacStrings.thisQRCodeContainsThePrivate
    public static let qrUnavailable = PlatformStrings.qrUnavailableOnTV
    public static let qrTooLarge = MacStrings.thisConfigurationIsTooLargeFor
    public static let exportFailed = MacStrings.theConfigurationCouldNotBe
    public static let done = MacStrings.done
    public static let replaceKey = MacStrings.updateKey
    public static let keyInput = MacStrings.newKeyBase64
    public static let clearPSK = MacStrings.removePresharedKey
    public static let valid = MacStrings.valid

    public static func peer(_ number: Int) -> String {
        MacStrings.peer(String(number))
    }
}
