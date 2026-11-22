// SPDX-License-Identifier: MIT
import Foundation

/// Interface churn on a usable path never restarts the saturated server retry schedule.
package enum UnderlayRestoration {
    package static func isRestored(_ event: UnderlayEvent, previous: UnderlayEvent, awaitingIPv6: Bool) -> Bool {
        guard !event.readFailed, event.satisfied, usable(event.snapshot) else { return false }
        let lost = (!previous.readFailed && !previous.satisfied) || !usable(previous.snapshot)
        let familyReturned = awaitingIPv6 && !previous.snapshot.ipv6DefaultRouteAvailable && event.snapshot.ipv6DefaultRouteAvailable
        return lost || familyReturned
    }

    private static func usable(_ snapshot: UnderlaySnapshot) -> Bool {
        snapshot.v4 != nil || snapshot.ipv6DefaultRouteAvailable
    }
}
