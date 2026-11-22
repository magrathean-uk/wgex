// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct AuthorisationTableTests {
    private static let owner: uid_t = 501
    private static let other: uid_t = 502
    private static let profile = UUID()

    private static func decide(
        _ request: Request,
        caller: uid_t = owner,
        console: Bool = true,
        admin: Bool = false,
        current: MacGlobalSettings? = .defaults,
        newer: Bool = false,
    ) -> AuthorisationDecision {
        AuthorisationTable.decide(
            request: request,
            callerUID: caller,
            isConsoleUser: console,
            hasAdminRight: admin,
            ownerUID: owner,
            currentSettings: current,
            clientIsNewer: newer,
        )
    }

    @Test(arguments: [uid_t(501), 502, 0])
    func `secure install status is readable but repair requires the admin right`(_ uid: uid_t) {
        #expect(Self.decide(.secureInstallStatus, caller: uid, console: false) == .allow)
        #expect(Self.decide(.performSecureInstall, caller: uid, console: false) == .deny(.adminRightRequired))
        #expect(Self.decide(.performSecureInstall, caller: uid, console: false, admin: true) == .allow)
    }

    @Test
    func `every request kind has a rule`() {
        #expect(Set(AuthorisationTable.rules.keys) == Set(RequestKind.allCases))
    }

    @Test
    func `owner-only requests refuse other users and root`() {
        for request in [
            Request.removeProfile(Self.profile, purgeSecrets: false),
            .stop(profileID: Self.profile, reason: .userRequested),
            .status,
        ] {
            #expect(Self.decide(request) == .allow)
            #expect(Self.decide(request, console: false) == .allow)
            #expect(Self.decide(request, caller: Self.other) == .deny(.notOwner))
            #expect(Self.decide(request, caller: 0) == .deny(.notOwner))
        }
    }

    @Test
    func `start needs owner and console user, or root`() {
        let start = Request.startIntent(profileID: Self.profile, transport: nil, hasSecrets: true)
        #expect(Self.decide(start) == .allow)
        #expect(Self.decide(start, console: false) == .deny(.notConsoleUser))
        #expect(Self.decide(start, caller: Self.other) == .deny(.notOwner))
        #expect(Self.decide(start, caller: 0, console: false) == .allow)
    }

    @Test
    func `tightening settings needs no admin right`() {
        var tighter = MacGlobalSettings.defaults
        tighter.lockdown = true
        tighter.allowLAN = false
        #expect(Self.decide(.setGlobalSettings(tighter)) == .allow)
        #expect(Self.decide(.setGlobalSettings(tighter), console: false) == .deny(.notConsoleUser))
    }

    @Test
    func `loosening settings needs the admin right`() {
        var locked = MacGlobalSettings.defaults
        locked.lockdown = true
        locked.allowLAN = false
        let unlock = MacGlobalSettings.defaults
        #expect(Self.decide(.setGlobalSettings(unlock), current: locked) == .deny(.adminRightRequired))
        #expect(Self.decide(.setGlobalSettings(unlock), admin: true, current: locked) == .allow)
        var longerWindow = MacGlobalSettings.defaults
        longerWindow.captiveWindowSeconds = 900
        #expect(Self.decide(.setGlobalSettings(longerWindow)) == .deny(.adminRightRequired))
        #expect(Self.decide(.setGlobalSettings(.defaults), current: nil) == .deny(.adminRightRequired))
    }

    @Test
    func `update and uninstall need the admin right`() {
        #expect(Self.decide(.uninstall(purgeState: true)) == .deny(.adminRightRequired))
        #expect(Self.decide(.uninstall(purgeState: true), admin: true) == .allow)
        #expect(Self.decide(.prepareForUpdate, admin: true) == .deny(.clientNotNewer))
        #expect(Self.decide(.prepareForUpdate, admin: true, newer: true) == .allow)
        #expect(Self.decide(.prepareForUpdate, newer: true) == .deny(.adminRightRequired))
    }

    @Test
    func `the admin right derives from the release base`() {
        #if DEBUG || WGEX_LAB_BUILD
            #expect(AuthorisationTable.adminRightName == "com.magrathean.WGEXApp.manage-protection.dev")
        #else
            #expect(AuthorisationTable.adminRightName == "com.magrathean.WGEXApp.manage-protection")
        #endif
    }
}
