// SPDX-License-Identifier: MIT

import NetworkExtension
import WGEXCore

/// The SDK's provider stop reason, retaining future raw values.
public enum ProviderStopReason: Sendable, Hashable {
    case none, userInitiated, providerFailed, noNetworkAvailable, unrecoverableNetworkChange
    case providerDisabled, authenticationCanceled, configurationFailed, idleTimeout
    case configurationDisabled, configurationRemoved, superceded, userLogout, userSwitch // spellchecker:disable-line
    case connectionFailed, sleep, appUpdate, internalError
    case unknown(Int)

    public init(rawValue: Int) {
        self = NEProviderStopReason(rawValue: rawValue).flatMap { Self.sdkReasons[$0] } ?? .unknown(rawValue)
    }

    private static let sdkReasons: [NEProviderStopReason: Self] = [
        .none: .none,
        .userInitiated: .userInitiated,
        .providerFailed: .providerFailed,
        .noNetworkAvailable: .noNetworkAvailable,
        .unrecoverableNetworkChange: .unrecoverableNetworkChange,
        .providerDisabled: .providerDisabled,
        .authenticationCanceled: .authenticationCanceled,
        .configurationFailed: .configurationFailed,
        .idleTimeout: .idleTimeout,
        .configurationDisabled: .configurationDisabled,
        .configurationRemoved: .configurationRemoved,
        .superceded: .superceded, // spellchecker:disable-line
        .userLogout: .userLogout,
        .userSwitch: .userSwitch,
        .connectionFailed: .connectionFailed,
        .sleep: .sleep,
        .appUpdate: .appUpdate,
        .internalError: .internalError,
    ]

    package var lifecycleReason: StopReason {
        switch self {
        case .userInitiated, .none, .idleTimeout, .sleep, .providerDisabled, .configurationDisabled: .userRequested
        case .configurationRemoved: .profileRemoved
        case .superceded: .superseded // spellchecker:disable-line
        case .userLogout, .userSwitch: .logout
        case .appUpdate: .update
        default: .failure
        }
    }
}
