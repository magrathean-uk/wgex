// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// Lifecycle notifications have independent latest-state revisions and five-second retries.
package enum MonitorAction: Sendable {
    package enum Kind: Hashable { case power, login }
    package struct Attempt: Sendable {
        package let action: MonitorAction
        package let revision: UInt64
        package let due: Duration
    }

    case power(PowerEvent), login(UInt32?)
    package var kind: Kind {
        switch self {
        case .power: .power
        case .login: .login
        }
    }
}

/// Producer receipt invalidates suspended actions without waiting for the serial consumer.
package final class MonitorActionRevisions: Sendable {
    private let latest = Mutex<[MonitorAction.Kind: UInt64]>([:])
    package func receive(_ kind: MonitorAction.Kind, revision: UInt64) {
        latest.withLock { $0[kind] = revision }
    }

    package func matches(_ kind: MonitorAction.Kind, revision: UInt64) -> Bool {
        latest.withLock { $0[kind] == revision }
    }

    package func clear() {
        latest.withLock { $0 = [:] }
    }
}
