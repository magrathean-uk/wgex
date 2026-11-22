// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    public extension MacShellModel {
        /// The app-wide state, as the menu's Status line reads it.
        var tunnelState: MacTunnelState {
            MacTunnelState(presentation: presentation, status: status)
        }

        /// One tunnel's state on its page. Unknown is app-wide, so every page shows it; a pending start names itself;
        /// the active tunnel's page (or every page while no tunnel is active, as with Lockdown blocking) shows the
        /// app's state; any other tunnel is Inactive.
        func tunnelState(for profile: TunnelProfile) -> MacTunnelState {
            let state = tunnelState
            if state == .unknown {
                return .unknown
            }
            if isStarting(profile) {
                return .activating
            }
            guard activeProfileID == nil || activeProfileID == profile.id else { return .inactive }
            return state
        }

        /// The latest statistics sample of the running generation, if it is fresh enough to describe as live
        /// (2.5 sampling intervals); never an older generation's counters.
        var liveSample: TunnelStatistics? {
            guard let sample = statistics, sample.generation == status.phase.generation?.rawValue,
                  sample.sampledAt <= now,
                  now.timeIntervalSince(sample.sampledAt) <= MacSessionTraffic.samplingInterval * 2.5 else { return nil }
            return sample
        }

        /// The measured rates between the last two samples of `sample`'s generation (SPEC E3), never the service's 0.
        func liveRates(_ sample: TunnelStatistics?) -> MacSessionTraffic.Rates? {
            sample.flatMap { traffic.rates(at: now, generation: $0.generation) }
        }
    }

#endif
