// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// The daemon's authorisation table as data (02 §5, ADR-012).
public enum AuthorisationTable {
    /// Admin right for loosening protection, updates and uninstall: a rule delegating to
    /// `authenticate-admin-nonshared` (an admin credential, not shared, 30 seconds; AdminRightDefinition).
    public static var adminRightName: String {
        #if DEBUG || WGEX_LAB_BUILD
            BuildIdentifiers.current.releaseVariant.base + ".manage-protection.dev"
        #else
            BuildIdentifiers.current.releaseVariant.base + ".manage-protection"
        #endif
    }

    /// One rule per request kind. `hello`, `closeCaptiveWindow` and
    /// `setStartBeforeLoginIntent` are not rows of the 02 §5 table; their rules
    /// here (any client; console user or root; as `start`) are phase-0 choices.
    public static let rules: [RequestKind: AuthorisationRule] = [
        .hello: .authenticatedClient,
        .secureInstallStatus: .authenticatedClient,
        .performSecureInstall: .adminRight,
        .subscribeEvents: .owner,
        .extendCaptiveWindow: .ownerAndConsoleUserOrRoot,
        .installProfile: .owner,
        .removeProfile: .owner,
        .status: .owner,
        .statistics: .owner,
        .logs: .owner,
        .diagnostics: .owner,
        .startIntent: .ownerAndConsoleUserOrRoot,
        .startCutover: .ownerAndConsoleUserOrRoot,
        .confirmCutover: .ownerAndConsoleUserOrRoot,
        .abortCutover: .owner,
        .selectTransport: .ownerAndConsoleUserOrRoot,
        .openCaptiveWindow: .ownerAndConsoleUserOrRoot,
        .setStartBeforeLoginIntent: .ownerAndConsoleUserOrRoot,
        .closeCaptiveWindow: .consoleUserOrRoot,
        .stop: .owner,
        .stopCurrent: .owner,
        .setGlobalSettings: .globalSettings,
        .prepareForUpdate: .adminRightAndNewerClient,
        .uninstall: .adminRight,
        .armOnDemand: .ownerAndConsoleUserOrRoot,
        .disarmOnDemand: .owner,
        .reportWiFiNetwork: .consoleUserApp,
    ]

    /// Decides a request.
    ///
    /// - Parameters:
    ///   - callerUID: Effective uid of the connection.
    ///   - isConsoleUser: The connection's audit session matches the console user.
    ///   - hasAdminRight: The daemon re-evaluated the external authorisation form, non-interactively,
    ///     against the current right definition.
    ///   - ownerUID: Owner of the profile the request names; nil when it names
    ///     none (a new install, a global request).
    ///   - currentSettings: Settings in force, to tell tightening from loosening;
    ///     nil treats every settings change as loosening.
    ///   - clientIsNewer: `clientBuild > daemonBuild` (for `prepareForUpdate`).
    ///   - isAppClient: The connection carries the app's signing identifier, not the CLI's.
    public static func decide(
        request: Request,
        callerUID: uid_t,
        isConsoleUser: Bool,
        hasAdminRight: Bool,
        ownerUID: uid_t?,
        currentSettings: MacGlobalSettings? = nil,
        clientIsNewer: Bool = false,
        isAppClient: Bool = false,
    ) -> AuthorisationDecision {
        guard let rule = rules[request.kind] else {
            return .deny(.noRule)
        }
        let caller = Caller(
            isOwner: ownerUID == nil || ownerUID == callerUID,
            isRoot: callerUID == 0,
            isConsoleUser: isConsoleUser,
            hasAdminRight: hasAdminRight,
        )
        switch rule {
        case .authenticatedClient:
            return .allow
        case .owner:
            return caller.isOwner ? .allow : .deny(.notOwner)
        case .ownerAndConsoleUserOrRoot:
            return caller.isRoot ? .allow : caller.ownerAndConsoleUser()
        case .consoleUserOrRoot:
            return caller.isRoot || caller.isConsoleUser ? .allow : .deny(.notConsoleUser)
        case .adminRight:
            return caller.adminRight()
        case .adminRightAndNewerClient:
            return caller.adminRight(clientIsNewer: clientIsNewer)
        case .consoleUserApp:
            return caller.consoleUserApp(isAppClient)
        case .globalSettings:
            guard case let .setGlobalSettings(requested) = request,
                  !loosens(from: currentSettings, to: requested)
            else {
                return caller.adminRight()
            }
            return caller.ownerAndConsoleUser()
        }
    }

    /// Recovery forbids weaker protection; authorisation still requires admin for any window-length change.
    public static func recoveryAllows(from current: MacGlobalSettings, to requested: MacGlobalSettings) -> Bool {
        (!current.lockdown || requested.lockdown) && (current.allowLAN || !requested.allowLAN)
            && (1 ... current.captiveWindowSeconds).contains(requested.captiveWindowSeconds)
            && requested.captiveWindowSeconds <= 3600
    }

    /// True when `requested` weakens protection compared with `current`.
    public static func loosens(from current: MacGlobalSettings?, to requested: MacGlobalSettings) -> Bool {
        guard let current else { return true }
        return (current.lockdown && !requested.lockdown)
            || (!current.allowLAN && requested.allowLAN)
            || current.captiveWindowSeconds != requested.captiveWindowSeconds
    }
}

/// Facts about the caller, all taken from the connection.
private struct Caller {
    let isOwner: Bool
    let isRoot: Bool
    let isConsoleUser: Bool
    let hasAdminRight: Bool

    func ownerAndConsoleUser() -> AuthorisationDecision {
        guard isOwner else { return .deny(.notOwner) }
        return isConsoleUser ? .allow : .deny(.notConsoleUser)
    }

    /// The app's signing identifier first, then the console session; root gets no exemption.
    func consoleUserApp(_ isAppClient: Bool) -> AuthorisationDecision {
        guard isAppClient else { return .deny(.notAppClient) }
        return isConsoleUser ? .allow : .deny(.notConsoleUser)
    }

    func adminRight(clientIsNewer: Bool = true) -> AuthorisationDecision {
        guard hasAdminRight else { return .deny(.adminRightRequired) }
        return clientIsNewer ? .allow : .deny(.clientNotNewer)
    }
}
