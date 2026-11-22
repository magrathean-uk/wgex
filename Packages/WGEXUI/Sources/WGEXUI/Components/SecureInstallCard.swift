// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// Compatibility name for the shared secure-install issue.
public typealias SecureInstallIssue = WGEXCore.SecureInstallIssue
/// Compatibility name for the shared secure-install state.
public typealias SecureInstallState = WGEXCore.SecureInstallState

public extension WGEXCore.SecureInstallState {
    /// Card title.
    var title: String {
        switch self {
        case .notReporting: UserStrings.serviceNotResponding
        case .checking: MacStrings.checkingSecureInstall
        case .verified: MacStrings.secureInstallVerified
        case .needsAttention: MacStrings.secureInstallNeedsAttention
        }
    }

    /// Evidence or consequence.
    var detail: String {
        switch self {
        case .notReporting:
            MacStrings.secureInstallNotReporting
        case .checking:
            MacStrings.verifyingTheAppLocationAndThe
        case .verified:
            MacStrings.wGEXIsInApplicationsAndThe
        case .needsAttention(.notInApplications):
            MacStrings.moveWGEXToTheApplications
        case .needsAttention(.bundleWritable):
            MacStrings.secureInstallNeededWGEXCanBe
        case .needsAttention(.serviceNotVerified):
            MacStrings.thePrivilegedServiceCouldNotBe
        case .needsAttention(.serviceOutdated):
            MacStrings.thePrivilegedServiceIsOlder
        }
    }

    /// Action title, if the state has one.
    var actionTitle: String? {
        switch self {
        case .checking, .verified: nil
        case .notReporting: MacStrings.verifyAgain
        case .needsAttention(.notInApplications): MacStrings.installInApplications
        case .needsAttention(.bundleWritable): MacStrings.secureInstall
        case .needsAttention(.serviceNotVerified): MacStrings.verifyAgain
        case .needsAttention(.serviceOutdated): MacStrings.updateService
        }
    }

    /// SF Symbol name.
    var glyph: String {
        switch self {
        case .notReporting: "questionmark.circle"
        case .checking: "hourglass"
        case .verified: "checkmark.seal.fill"
        case .needsAttention: "exclamationmark.triangle.fill"
        }
    }

    /// Colour token for the glyph.
    var colour: StateColor {
        switch self {
        case .checking, .notReporting: .unknown
        case .verified: .protected
        case .needsAttention: .blocked
        }
    }
}

/// Card for the secure install step.
public struct SecureInstallCard: View {
    private let state: SecureInstallState
    private let onAction: () -> Void

    /// Creates a card.
    public init(state: SecureInstallState, onAction: @escaping () -> Void) {
        self.state = state
        self.onAction = onAction
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.medium) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.small) {
                Image(systemName: state.glyph)
                    .accessibilityHidden(true)
                    .foregroundStyle(state.colour.color)
                Text(state.title)
                    .font(Typography.cardTitle)
            }
            Text(state.detail)
                .font(Typography.body)
                .foregroundStyle(.secondary)
            if let actionTitle = state.actionTitle {
                Button(actionTitle, action: onAction).wgexControl(.service, "actionTitle", label: actionTitle)
                    .buttonStyle(.glassProminent)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
        .accessibilityIdentifier("wgex.service.secureInstall")
    }

    /// "Secure install needs attention. Move WGEX …".
    public static func accessibilityLabel(for state: SecureInstallState) -> String {
        MacStrings.warningAnnouncement(String(state.title), String(state.detail))
    }
}
