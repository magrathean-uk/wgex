// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import WGEXCore

/// Deterministic simulator scenarios. Unknown or missing values never enable a scenario.
internal enum FakeScenario: String, CaseIterable {
    case unprotected, connecting, protected, reasserting, blocked, unknown

    internal static func parse(arguments: [String]) -> FakeScenario? {
        guard let index = arguments.firstIndex(of: "-WGEXFakeScenario"), arguments.indices.contains(index + 1) else { return nil }
        return FakeScenario(rawValue: arguments[index + 1])
    }

    internal var status: TunnelStatus {
        let generation = Generation(rawValue: 1)
        var status = TunnelStatus.idle
        switch self {
        case .unprotected: break
        case .connecting: status.phase = .preparing(generation); status.protection = .unprotected
        case .protected: status.phase = .active(generation); status.protection = .protected
        case .reasserting: status.phase = .reasserting(generation, reason: .pathChanged); status.protection = .unprotected
        case .blocked: status.phase = .failed(.timedOut, blockedByPolicy: true, needsSecrets: false); status.protection = .blocked
        case .unknown: status.protection = .unknown
        }
        return status
    }
}
