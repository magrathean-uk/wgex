// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Text for ``WGEXCore/TunnelEvent`` rows in the events timeline. Events
/// carry no free-form text, and error payloads are never shown.
public nonisolated enum EventDescription {
    /// Glyph and sentence for one event.
    public static func describe(_ kind: TunnelEvent.Kind) -> (glyph: String, text: String) {
        switch kind {
        case .phaseChanged: ("arrow.triangle.2.circlepath", MacStrings.statusChanged)
        case .handshakeCompleted: ("checkmark.circle", MacStrings.handshakeCompleted)
        case .txWithoutRx: ("exclamationmark.triangle", MacStrings.noReplyFromThePeer)
        case .endpointChanged: ("arrow.left.arrow.right", MacStrings.peerEndpointChanged)
        case .transportChanged: ("arrow.triangle.branch", MacStrings.transportChanged)
        case .pathChanged: ("network", MacStrings.networkChangedReconnecting)
        case let .protectionChanged(state): ("shield", protectionText(state))
        case let .failed(error): ("xmark.octagon", MacStrings.connectionFailed + errorText(error))
        }
    }

    /// Short protection wording for the timeline.
    public static func protectionText(_ state: ProtectionState) -> String {
        switch state {
        case .protected: MacStrings.protected
        case .blocked: MacStrings.trafficBlocked
        case .captiveWindow: MacStrings.captiveWindowOpened
        case .unprotected: MacStrings.unprotected
        case .unsupported: MacStrings.killSwitchNotAvailableOnThis
        case .unknown: MacStrings.protectionCannotBeVerified
        }
    }

    /// Short error wording; payloads (configuration text) are never shown.
    // Exhaustive fixed-copy catalogue, matching MacErrorCopy's catalogue convention.
    // swiftlint:disable:next cyclomatic_complexity
    public static func errorText(_ error: TunnelError) -> String {
        switch error {
        case .anotherTunnelActive: MacStrings.anotherTunnelIsConnected
        case .profileNotFound: MacStrings.tunnelNotFound
        case let .invalidConfiguration(reason): configurationText(reason)
        case .serviceRecovering: MacStrings.serviceRecoveringTitle
        case .revisionConflict: MacStrings.revisionConflictConsequence
        case .busy: MacStrings.busyConsequence
        case .secretsUnavailable: MacStrings.keysAreUnavailable
        case .backendUnavailable: MacStrings.backgroundServiceUnavailable
        case .permissionDenied: MacStrings.permissionDenied
        case .timedOut: MacStrings.timedOut
        case let .engine(code): MacStrings.engineError(String(code))
        case .cancelled: "cancelled"
        }
    }

    /// Wording for a finite configuration reason; never the configuration itself.
    private static func configurationText(_ reason: InvalidConfigurationReason) -> String {
        switch reason {
        case .invalidProfile, .statisticsInterval: MacStrings.theConfigurationIsInvalid
        case .multipleBootProfiles: MacStrings.moreThanOneProfileStartsBeforeLogin
        }
    }

    /// Newest first, at most `limit` (the backend bound is 32).
    public static func timeline(_ events: [TunnelEvent], limit: Int = TunnelStatus.recentEventLimit) -> [TunnelEvent] {
        Array(events.suffix(limit).reversed())
    }
}
