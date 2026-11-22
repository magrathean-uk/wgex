// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    public extension MacShellModel {
        var handshakeValue: StatValue {
            guard let date = displayedStatistics?.peers.compactMap(\.lastHandshake).max() else { return .unavailable }
            return .age(since: date, now: now)
        }

        var downloadValue: StatValue {
            displayedStatistics?.peers.isEmpty == false ? .rate(status.health.rxRate) : .unavailable
        }

        var uploadValue: StatValue {
            displayedStatistics?.peers.isEmpty == false ? .rate(status.health.txRate) : .unavailable
        }

        var connectedDuration: String {
            guard !selectedIsInactive, let start = traffic.startedAt else { return MacStrings.unavailable }
            return UIFormat.age(start, now: now)
        }

        var killSwitchDescription: String {
            if selectedIsInactive {
                return MacStrings.inactive
            }
            if presentation.isStale {
                return presentation.verdict == .unknown ? MacStrings.statusUnknown : MacStrings.unknownServiceStatusIsStale
            }
            switch status.protection {
            case .protected: return MacStrings.armed
            case .blocked: return MacStrings.blockingTraffic
            case .captiveWindow: return MacStrings.suspendedDuringCaptiveWindow
            case .unprotected: return MacStrings.offNotConnected
            case .unsupported: return MacStrings.unsupported
            case .unknown: return MacStrings.protectionCannotBeVerified
            }
        }
    }
#endif
