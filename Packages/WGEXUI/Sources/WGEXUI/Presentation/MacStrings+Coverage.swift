// SPDX-License-Identifier: MIT

/// Enumerated static copy for the string regression suite.
public nonisolated extension MacStrings {
    /// All static catalogue values; dynamic templates are exercised by presenter tests.
    /// M07-T04, T05 and T06 append their copy through `MacStrings+Coverage+TunnelSheets|Pages|Setup.swift`.
    static let catalogue: [String] =
        aboutCatalogue + accessibilityCatalogue + detailsCatalogue + editorCatalogue + eventsCatalogue + exportCatalogue +
        formattingCatalogue + importCatalogue + onboardingCatalogue + profilesCatalogue + protectionCatalogue + serviceCatalogue +
        workflowCatalogue + sessionCatalogue + tunnelPageCatalogue + settingsCatalogue + shellCatalogue + statusCatalogue +
        transportCatalogue +
        onDemandCatalogue + tunnelSheetsCatalogue + appPagesCatalogue + setupCatalogue + exclusionsCatalogue

    private static let aboutCatalogue: [String] = [
        acknowledgementsCouldNotBeLoaded, thanksToWireGuard, version, wireGuardTrademarkDisclaimer, acknowledgements,
        about, openSourceWireGuardClient, wGEXIsMITLicensedItUsesWire, wireGuardLicence, wombatLicence,
        firezoneSwiftComponents, firezoneLicence, thirdPartyLicenceNoticesAre, wireGuardIsARegistered, acknowledgementsUnavailable,
    ]

    private static let accessibilityCatalogue: [String] = [
        staleQualifier, captiveAnnouncementPrefix, connectionStatus,
    ]

    private static let detailsCatalogue: [String] = [
        details, status,
    ]

    private static let editorCatalogue: [String] = [
        dns, mtu, name, addresses, endpoint,
        interface, listenPort, allowedIPs, publicKey,
        profileEditor, privateKey, presharedKey, searchDomains, peers,
        persistentKeepaliveSeconds, keepaliveValidation, ipv6Policy, tunnelIPv6, blockIPv6OutsideTheTunnel,
        allowIPv6OutsideTheTunnel, ipv6OutsideTunnelConsequence, dnsPolicy, allDNSThroughTheTunnel, splitDNS, systemDNS,
        dnsMatchDomains, macOSOptions, save, discardChanges, yourUnsavedProfileChangesWill,
        keepEditing, generateKeypair, replacingThisKeyChangesThe, addPeer, removePeer,
        movePeerUp, movePeerDown, excludePrivateNetworksRemovesR, errors, warnings,
        theProfileCouldNotBeSavedCheck, aKeypairCouldNotBeGeneratedTry, saveUnavailableUntilErrorsAre, updateKey, newKeyBase64,
        removePresharedKey, valid, address, allowedIP, remove,
        allTraffic, excludePrivateNetworks, add, copy, hide,
        revealOnce, revealedOnceOpenTheEditorAgain, allTrafficExceptPrivateNetworks, allIPv4TrafficExceptPrivate, singleRange,
        none,
    ]

    private static let eventsCatalogue: [String] = [
        paused, live, eventsFormat,
        timeline, rawLog, rawLogsAreNotAvailableFromThis, noLogLinesYet, saveLog, theLogCouldNotBeSaved,
        statusChanged, handshakeCompleted, noReplyFromThePeer, peerEndpointChanged,
        transportChanged, networkChangedReconnecting, connectionFailed, captiveWindowOpened, killSwitchNotAvailableOnThis,
        anotherTunnelIsConnected, tunnelNotFound, theConfigurationIsInvalid, keysAreUnavailable, backgroundServiceUnavailable,
        permissionDenied, timedOut, events, noEventsYet,
    ]

    private static let exportCatalogue: [String] = [
        export, exportProfile, shareWithoutKeys, exportConfigurationFile, exportPrivateKey,
        thisFileContainsThePrivateKey, exportFileWithKeys, showQRCode, thisQRCodeContainsThePrivate, thisConfigurationIsTooLargeFor,
        theConfigurationCouldNotBe, exportAllTunnels, exportAllTitle, exportAllWarning, exportAllWithKeys, exportAllFilename,
        exportAllTooMany, exportAllTooLarge, importTunnelsCommand,
    ]

    private static let formattingCatalogue: [String] = [
        text1Minute, b, mB, gB, tB,
        ago, text1Second,
    ]

    private static let importCatalogue: [String] = [
        paste,
        importLabel, routes,
        aMatchingProfileAlreadyExists, duplicate, keepBoth,
        replace, usingTheSamePrivateKeyOnTwo, importCouldNotBeCompletedTry,
        importFromFile, theProfileCouldNotBeImported, reviewImportTitle, importAndConnectAction,
        duplicateProfiles, aProfileWithThisNameAlready, thisPublicKeyIsAlready, postUpHooksAreNotSupportedAnd,
        theConfigurationIsNotValidUTF8,
        importUnavailableUntilErrors,
    ]

    private static let onboardingCatalogue: [String] = [
        off, connectAtLogin, connectAtBootBeforeLogin,
        automaticFailover,
        back,
        continueLabel,
    ]

    private static let profilesCatalogue: [String] = [
        defaultTunnel, chooseATunnel, tunnels,
        noTunnelsTitle, noEndpoint, profiles,
    ]

    private static let protectionCatalogue: [String] = [
        captiveWindow, text5Minutes, text10Minutes,
        unprotectedWebTrafficIsAllowed, allowLAN, openCaptiveWindow, confirmOpenCaptiveWindow,
        endCaptiveWindow, killSwitch, lockdown, allowLocalNetwork,
        armed, blockingTraffic, suspendedDuringCaptiveWindow, offNotConnected, captiveWindowEndedRestoring,
        readToTheEndToContinue, turnOn, keepOff,
    ]

    private static let serviceCatalogue: [String] = [
        secureInstall, hostGuardBackgroundService, approveAndStartTheBackground, addAProfileBeforeChoosingA,
        completeSecureInstallBefore, simulationNoVPNOrSystem, connectingToTheDaemon, daemonDisconnectedStatus,
        downgradeState, downgradeDetected,
        uninstallWGEXEllipsis, uninstallWGEXQuestion, uninstallEffects, uninstallKeepsProfiles, alsoRemoveProfilesAndSettings,
        uninstallEllipsis, uninstalling, tryAgain, notNow, finishUninstallingWGEX, finishUninstallExplanation,
        finishUninstallResumeExplanation, finishUninstall, uninstallDaemonFailed, uninstallServiceFailed, uninstallAppDataFailed,
        wgexIsUninstalled, wgexCanBeMovedToTheBin,
        simulateApproval, backgroundService,
        checkingSecureInstall, secureInstallVerified, secureInstallNeedsAttention, verifyingTheAppLocationAndThe,
        wGEXIsInApplicationsAndThe,
        moveWGEXToTheApplications, secureInstallNeededWGEXCanBe, thePrivilegedServiceCouldNotBe, thePrivilegedServiceIsOlder,
        installInApplications,
        verifyAgain, updateService, inProgress, notStarted, needsAttention,
        needsApproval, approved, approval, allowWGEXInSystemSettingsUnder, enabled,
        running, waitingForTheBackgroundService, registered, registerTheBackgroundServiceTo, theBackgroundServiceSLaunchd,
        openSystemSettings, startBeforeLogin, theMacMustBeUnlockedBeforeThe, startingBeforeLoginRequires, secureInstallNeededSecureThe,
    ]

    private static let sessionCatalogue: [String] = [
        download, upload,
    ]

    private static let tunnelPageCatalogue: [String] = [
        activate, deactivate, trafficBlockedDetail, usingHotelWiFi, openBackgroundService,
        trafficGroup, serverGroup, advancedGroup, lastHandshake, downloadAndUpload,
        tunnelAddress, ipv6Address, keepalive, localNetwork, connectOnDemand,
        connectAutomatically, thisMacsPublicKey, killSwitchOn, killSwitchBlocking, killSwitchPaused,
        localNetworkAllowed, localNetworkNotAllowed, startupNever, startupAtLogin, startupAtStartUp,
        startupNote, onDemandEthernetAndWiFi, editEllipsis, deleteTunnel,
    ]

    private static let settingsCatalogue: [String] = [
        backgroundServicePage, logPage, addTunnel, sidebarBlocked,
        general, hideDockIcon, protection, notifications,
        notificationDeliveryArrivesInA, diagnostics, standard,
        exportDiagnostics, exportDiagnosticsEllipsis, exportEllipsis, includeLogs, theArchiveHoldsTheseRedactedItems,
        diagnosticsContentRedactedLogs, diagnosticsContentFirewall, diagnosticsContentRoutes, diagnosticsContentManifest,
        diagnosticsSaved, theDiagnosticsCouldNotBeSaved, diagnosticsFilename("x"),
        service, network,
        automatic, settingsCommand, settingsTitle,
    ]

    private static let shellCatalogue: [String] = [
        dismiss,
        cancel, quitWGEX,
        done,
        aboutWGEX, setupCommand, appName, tunnelMenu,
    ]

    private static let statusCatalogue: [String] = [
        recoveryNoPrimaryInterface, recoveryProfileUnavailable, recoveryResolverUnavailable,
        recoveryMonitorStartFailed, recoveryReconciliationFailed, recoveryIntentStartFailed, recoveryBlockingPolicyFailed,
        moreThanOneProfileStartsBeforeLogin,
        stale, trafficBlocked, unavailable, inactive, unknownServiceStatusIsStale,
        unsupported, protected, connecting, checkingTheTunnelAndProtection, reconnecting,
        openWGEXToReconnectTraffic, theConnectionFailedTheKill, disconnectingTheKillSwitchIs, theKillSwitchIsBlockingTraffic,
        signInToThisNetwork,
        unprotected, trafficCanLeaveOutsideTheTunnel, thisDeviceCannotEnforceAKill, connected, notConnected,
        noReportYet, trafficOutsideTheTunnelIs, unprotectedMeanwhile, networkChangedChecking, wokeFromSleepChecking,
        switchingTransportChecking, tryingTheNextEndpointChecking, theTunnelCouldNotBeVerified, vpnExtensionStatusIsUnavailable,
        secureInstallIsNotComplete,
        networkSettingsAreStillBeing, theReportedStateDoesNotMatch, trafficMayLeaveOutsideThe, vpnExtension, noKillSwitch,
        unknown, statusUnknown, connectedTransferring, connectedIdle, connectedNoNetworkAvailable,
        slowReplies, noResponse, noNetwork, noHandshakeYet, activeTunnel,
        protectionCannotBeVerified, lastKnown, active,
    ]

    private static let transportCatalogue: [String] = [
        directWireGuard, transport, chooseTransport, transports,
        directWireGuardUDP, experimentalRelayTransports, relayTransportsAreExperimental,
    ]
    private static let workflowCatalogue: [String] = [
        finishingUpdate, needsApprovalAgain, serviceResponding, serviceRecoveringTitle,
        serviceRecoveringConsequence, serviceRecoveringAction, serviceRecoveringUnmeasured,
        secureInstallNotReporting,
        revisionConflictTitle, revisionConflictConsequence, revisionConflictAction,
        dnsUnverifiedTitle, dnsUnverifiedConsequence, dnsUnverifiedAction,
        deletionBlockedTitle, deletionBlockedConsequence, deletionBlockedAction,
        loginItemTitle, loginItemConsequence, loginItemAction,
        fixtureUnavailableTitle, fixtureUnavailableConsequence, fixtureUnavailableAction,
        importSourceTitle, importSourceConsequence, importSourceAction,
        configurationTitle, configurationConsequence, configurationAction,
        missingProfileTitle, missingProfileConsequence, missingProfileAction,
        secretsTitle, secretsConsequence, secretsAction,
        serviceTitle, serviceConsequence, serviceAction,
        permissionTitle, permissionConsequence, permissionAction,
        timeoutTitle, timeoutConsequence, timeoutAction,
        engineTitle, engineConsequence, engineAction,
        cancelledTitle, cancelledConsequence, cancelledAction,
        secureCancelledTitle, secureCancelledConsequence, secureCancelledAction,
        hostGuardTitle, hostGuardConsequence, hostGuardAction,
        unsupportedTitle, unsupportedConsequence, unsupportedAction,
        protocolMismatchTitle, protocolMismatchConsequence, protocolMismatchAction,
        downgradeTitle, downgradeConsequence, downgradeAction,
        secureRequiredTitle, secureRequiredConsequence, secureRequiredAction,
        busyTitle, busyConsequence, busyAction,
        activeProfileTitle, activeProfileConsequence, activeProfileAction,
        documentTitle, documentConsequence, documentAction,
        storeTitle, storeConsequence, storeAction,
        unknownTitle, unknownConsequence, unknownAction,
        deleteProfileAction,

        quarantinedProfiles,
        menuUnknown, menuOpenWGEX, manageTunnels, importTunnelsFromFile, menuSignInConfirmation, menuSignInWarning, menuSignIn,
        menuEndSignIn,
        menuBlocked,
        menuSignInOpen, menuServiceUnavailable, menuWaiting, menuActivating, menuReconnecting, menuTrafficBlocked, menuNotProtected,
        menuInterface, menuAddress, menuIPv6Address, menuHandshake, menuKillSwitch, menuKillSwitchOn,
    ]
}
