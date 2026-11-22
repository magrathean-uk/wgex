// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    public extension MacShellModel {
        /// Longest allowed-networks list the menu joins in full; longer lists show the editor's summary.
        nonisolated static let menuNetworksJoinLimit = 3

        /// The active profile's allowed networks for the menu line, nil when there is no profile.
        var menuNetworks: String? {
            guard let profile = activeProfile else { return nil }
            var seen = Set<String>()
            let texts = profile.peers.flatMap(\.allowedIPs).map(\.description).filter { seen.insert($0).inserted }
            guard !texts.isEmpty else { return MacStrings.allowedNetworksLine(MacStrings.none) }
            if texts.count <= Self.menuNetworksJoinLimit {
                return MacStrings.allowedNetworksLine(texts.joined(separator: ", "))
            }
            return MacStrings.allowedNetworksLine(AllowedIPsModel(texts).summary)
        }

        /// Global connection commands stay available while an inactive selection or other work is busy.
        var canToggleActiveConnection: Bool {
            if menuPrimaryControl.armsOrDisarms {
                return canChangeOnDemand
            }
            return switch designPresentation.action {
            case .disconnect, .cancel, .checkAgain: !hostGuarded
            default: canConnect
            }
        }

        /// Derives current or last-known display evidence without changing the shell's freshness timestamp.
        var presentation: ProtectionPresentation {
            var displayed = status
            if !simulated, status.measuredAt == nil {
                displayed.protection = .unknown
            }
            if !simulated, !status.hasRequiredPolicyEvidence(at: daemonHooks.continuousNow()) {
                displayed.protection = .unknown
            }
            if !simulated, let measured = status.measuredAtContinuous,
               daemonHooks.continuousNow() - measured >= Staleness.threshold
            {
                displayed.protection = .unknown
            }
            var result = ProtectionPresentation(status: displayed, context: ProtectionContext(
                platform: .mac, now: now, staleness: presentationStaleness,
                unknownReason: reportingReason,
            ))
            if connectionRequestInFlight {
                result.action = .cancel
            }
            return result
        }

        private var presentationStaleness: Staleness {
            if status.verificationExpired, !status.reportingUnavailable {
                return .fresh
            }
            if lastReceivedReportAt == nil, status.measuredAt == nil {
                return .stale(since: .distantPast)
            }
            if !simulated, status.notReportingSince != nil, !status.reportingUnavailable,
               case .connected = daemonConnection
            {
                return .fresh
            }
            if lastStatusAt == nil, let lastReceivedReportAt {
                return .stale(since: lastReceivedReportAt)
            }
            if simulated {
                return .evaluate(lastUpdate: lastStatusAt, now: now)
            }
            if status.reportingUnavailable {
                return .stale(since: lastReceivedReportAt ?? .distantPast)
            }
            if case .disconnected = daemonConnection, lastReceivedReportAt != nil {
                return .stale(since: lastReceivedReportAt ?? .distantPast)
            }
            // Connected reporting gaps use the unknown copy; cached evidence is never made current.
            return .fresh
        }

        private var reportingReason: UnknownReason {
            if status.verificationExpired {
                return .verificationFailed
            }
            if let since = status.notReportingSince {
                return .notReporting(since: since)
            }
            if let measured = status.measuredAtContinuous,
               daemonHooks.continuousNow() - measured >= Staleness.threshold
            {
                return .notReporting(since: status.measuredAt ?? now)
            }
            if status.measuredAt == nil {
                return .notReporting(since: lastReceivedReportAt ?? now)
            }
            switch secureInstall {
            case .needsAttention, .checking: return .secureInstallPending
            case .verified, .notReporting: return .verificationFailed
            }
        }
    }
#endif
