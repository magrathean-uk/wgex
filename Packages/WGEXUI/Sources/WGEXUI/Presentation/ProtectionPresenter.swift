// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

public nonisolated extension ProtectionPresentation {
    /// Maps a backend status to what every status surface shows (plan 06 §3,
    /// ADR-009, `docs/protection-semantics.md`). Stale and unknown states
    /// never carry a protection colour.
    init(status: TunnelStatus, context: ProtectionContext = ProtectionContext()) {
        if context.staleness.since == .distantPast {
            self = ProtectionPresentation(
                verdict: .unknown, glyph: ProtectionVerdict.unknown.glyph, ring: .none, colour: .unknown,
                primary: MacStrings.statusUnknown, secondary: MacStrings.noReportYet, action: .checkAgain, isStale: true,
            )
        } else if let since = context.staleness.since {
            self = Self.stale(since: since, now: context.now)
        } else {
            self = Self.fresh(status, verdict: Self.verdict(for: status, platform: context.platform), context: context)
            if let reason = status.recoveryFailureReason {
                secondary = Self.joinSentences([secondary, MacStrings.serviceRecoveringTitle])
                recoveryDetail = Self.joinSentences([Self.recoveryLine(reason)])
            }
        }
        applyReporter(status)
    }

    /// The verdict for a status, before staleness is applied.
    static func verdict(for status: TunnelStatus, platform: ProtectionContext.Platform) -> ProtectionVerdict {
        if let operation = operationVerdict(status) {
            return operation
        }
        switch status.protection {
        case .unknown:
            return .unknown
        case .captiveWindow:
            return platform == .mac ? .captiveWindow : .unknown
        case .protected, .blocked, .unprotected, .unsupported:
            break
        }
        switch status.phase {
        case .preparing, .configuring:
            return .connecting
        case .reasserting:
            return .reasserting
        case .idle, .active, .captiveWindow, .stopping, .failed:
            return settledVerdict(status.protection, platform: platform)
        }
    }

    private mutating func applyReporter(_ status: TunnelStatus) {
        guard status.serviceResponding else { return }
        reporterDetail = MacStrings.serviceResponding
        guard !isStale, action == .checkAgain else { return }
        switch status.phase {
        case .idle: action = .connect
        case .preparing, .configuring: action = .cancel
        case .active, .reasserting, .stopping: action = .disconnect
        case .captiveWindow: action = .endCaptiveWindow
        case .failed(_, blockedByPolicy: true, _): action = .disconnect
        case .failed: action = .reconnect
        }
    }

    private static func operationVerdict(_ status: TunnelStatus) -> ProtectionVerdict? {
        guard status.serviceResponding, status.operationInFlight else { return nil }
        switch status.phase {
        case .preparing, .configuring: return .connecting
        case .reasserting: return .reasserting
        default: return nil
        }
    }

    private static func fresh(_ status: TunnelStatus, verdict: ProtectionVerdict, context: ProtectionContext) -> ProtectionPresentation {
        switch verdict {
        case .protected: protected(status.health, now: context.now)
        case .connecting: connecting(status.protection)
        case .reasserting: reasserting(status)
        case .blocked: blocked(status.phase)
        case .captiveWindow: captiveWindow(status.protection, now: context.now, userInitiated: context.userInitiated)
        case .unprotected: unprotected(userInitiated: context.userInitiated)
        case .unsupported: unsupported(status, context: context)
        case .unknown, .stale, .inactive: unknown(unknownReason(status, context: context), context: context)
        }
    }

    private static func settledVerdict(_ protection: ProtectionState, platform: ProtectionContext.Platform) -> ProtectionVerdict {
        switch protection {
        case .protected: .protected
        // tvOS never claims blocked (ADR-009): a report of it is inconsistent.
        case .blocked: platform == .tvOS ? .unknown : .blocked
        case .unprotected: .unprotected
        case .unsupported: .unsupported
        case .captiveWindow, .unknown: .unknown
        }
    }

    private static func unknownReason(_ status: TunnelStatus, context: ProtectionContext) -> UnknownReason {
        if case .unknown = status.protection {
            return context.unknownReason ?? .unspecified
        }
        return .inconsistentState
    }

    private static func protected(_ health: TunnelHealth, now: Date) -> ProtectionPresentation {
        ProtectionPresentation(
            verdict: .protected,
            glyph: ProtectionVerdict.protected.glyph,
            ring: .solid,
            colour: .protected,
            primary: MacStrings.protected,
            secondary: HealthDescription.line(for: health, now: now),
            action: .disconnect,
            feedback: .success,
            healthChip: HealthDescription.chip(for: health),
        )
    }

    private static func connecting(_ protection: ProtectionState) -> ProtectionPresentation {
        ProtectionPresentation(
            verdict: .connecting,
            glyph: ProtectionVerdict.connecting.glyph,
            ring: .indeterminate,
            colour: .unknown,
            primary: MacStrings.connecting,
            secondary: MacStrings.checkingTheTunnelAndProtection + meanwhile(protection),
            action: .cancel,
        )
    }

    private static func reasserting(_ status: TunnelStatus) -> ProtectionPresentation {
        var reason = ReassertReason.pathChanged
        if case let .reasserting(_, current) = status.phase {
            reason = current
        }
        return ProtectionPresentation(
            verdict: .reasserting,
            glyph: ProtectionVerdict.reasserting.glyph,
            ring: .dashed,
            colour: .unknown,
            primary: MacStrings.reconnecting,
            secondary: reassertLine(reason) + meanwhile(status.protection),
            action: .disconnect,
        )
    }

    private static func blocked(_ phase: TunnelPhase) -> ProtectionPresentation {
        let secondary = switch phase {
        case .failed(_, _, needsSecrets: true):
            MacStrings.openWGEXToReconnectTraffic
        case .failed:
            MacStrings.theConnectionFailedTheKill
        case .stopping:
            MacStrings.disconnectingTheKillSwitchIs
        case .idle, .preparing, .configuring, .active, .reasserting, .captiveWindow:
            MacStrings.theKillSwitchIsBlockingTraffic
        }
        return ProtectionPresentation(
            verdict: .blocked,
            glyph: ProtectionVerdict.blocked.glyph,
            ring: .solid,
            colour: .blocked,
            primary: MacStrings.trafficBlocked,
            secondary: secondary,
            action: {
                if case .failed = phase {
                    return .disconnect
                }; return .reconnect
            }(),
            feedback: .warning,
        )
    }

    private static func captiveWindow(_ protection: ProtectionState, now: Date, userInitiated: Bool) -> ProtectionPresentation {
        var expires = now
        if case let .captiveWindow(date) = protection {
            expires = date
        }
        return ProtectionPresentation(
            verdict: .captiveWindow,
            glyph: ProtectionVerdict.captiveWindow.glyph,
            ring: .solid,
            colour: .unprotected,
            primary: MacStrings.signInToThisNetwork,
            secondary: CaptiveWindowCopy.message(remaining: expires.timeIntervalSince(now)),
            action: .endCaptiveWindow,
            feedback: userInitiated ? .none : .warning,
            countdownExpiry: expires,
        )
    }

    private static func unprotected(userInitiated: Bool) -> ProtectionPresentation {
        ProtectionPresentation(
            verdict: .unprotected,
            glyph: ProtectionVerdict.unprotected.glyph,
            ring: .none,
            colour: .unprotected,
            primary: MacStrings.unprotected,
            secondary: MacStrings.trafficCanLeaveOutsideTheTunnel,
            action: .connect,
            feedback: userInitiated ? .none : .warning,
        )
    }

    private static func unsupported(_ status: TunnelStatus, context: ProtectionContext) -> ProtectionPresentation {
        let connected = if case .active = status.phase {
            true
        } else {
            false
        }
        let cannot = context.platform == .tvOS ? PlatformStrings.appleTVCannotEnforceAKillSwitch : MacStrings.thisDeviceCannotEnforceAKill
        return ProtectionPresentation(
            verdict: .unsupported,
            glyph: ProtectionVerdict.unsupported.glyph,
            ring: connected ? .solid : .none,
            colour: .unknown,
            primary: connected ? MacStrings.connected : MacStrings.notConnected,
            secondary: connected ? MacStrings.trafficCanLeaveOutsideThe(String(cannot)) :
                MacStrings.trafficLeavesOutsideTheTunnel(String(cannot)),
            action: connected ? .disconnect : .connect,
            healthChip: connected ? HealthDescription.chip(for: status.health) : nil,
        )
    }

    private static func unknown(_ reason: UnknownReason, context: ProtectionContext) -> ProtectionPresentation {
        var presentation = ProtectionPresentation(
            verdict: .unknown,
            glyph: ProtectionVerdict.unknown.glyph,
            ring: .solid,
            colour: .unknown,
            primary: MacStrings.protectionCannotBeVerified,
            secondary: reasonLine(reason, context: context),
            action: .checkAgain,
        )
        if case .notReporting = reason {
            presentation.isStale = true
        }
        return presentation
    }

    private static func stale(since: Date, now: Date) -> ProtectionPresentation {
        let secondary = UserStrings.staleReport(UIFormat.ago(since, now: now))
        return ProtectionPresentation(
            verdict: .stale,
            glyph: ProtectionVerdict.stale.glyph,
            ring: .none,
            colour: .unknown,
            primary: UserStrings.serviceNotResponding,
            secondary: secondary,
            action: .checkAgain,
            isStale: true,
        )
    }

    private static func meanwhile(_ protection: ProtectionState) -> String {
        switch protection {
        case .blocked: MacStrings.trafficOutsideTheTunnelIs
        case .unprotected, .unsupported: MacStrings.unprotectedMeanwhile
        case .protected, .captiveWindow, .unknown: ""
        }
    }

    private static func reassertLine(_ reason: ReassertReason) -> String {
        switch reason {
        case .pathChanged: MacStrings.networkChangedChecking
        case .wake: MacStrings.wokeFromSleepChecking
        case .transportSwitch: MacStrings.switchingTransportChecking
        case .endpointRotation: MacStrings.tryingTheNextEndpointChecking
        }
    }

    private static func reasonLine(_ reason: UnknownReason, context: ProtectionContext) -> String {
        switch reason {
        case .verificationFailed:
            MacStrings.theTunnelCouldNotBeVerified
        case let .notReporting(since):
            MacStrings.hasNotReportedFor(String(context.platform.reporterName), String(UIFormat.age(since, now: context.now)))
        case .extensionUnavailable:
            MacStrings.vpnExtensionStatusIsUnavailable
        case .secureInstallPending:
            MacStrings.secureInstallIsNotComplete
        case .settingsPending:
            MacStrings.networkSettingsAreStillBeing
        case .inconsistentState:
            MacStrings.theReportedStateDoesNotMatch
        case .unspecified:
            MacStrings.trafficMayLeaveOutsideThe
        }
    }

    private static func recoveryLine(_ reason: RecoveryFailureReason) -> String {
        switch reason {
        case .noPrimaryInterface: MacStrings.recoveryNoPrimaryInterface
        case .profileUnavailable: MacStrings.recoveryProfileUnavailable
        case .multipleBootProfiles: MacStrings.moreThanOneProfileStartsBeforeLogin
        case .resolverUnavailable: MacStrings.recoveryResolverUnavailable
        case .monitorStartFailed: MacStrings.recoveryMonitorStartFailed
        case .reconciliationFailed: MacStrings.recoveryReconciliationFailed
        case .intentStartFailed: MacStrings.recoveryIntentStartFailed
        case .blockingPolicyFailed: MacStrings.recoveryBlockingPolicyFailed
        case .secureInstallRequired: MacStrings.secureInstallIsNotComplete
        }
    }
}
