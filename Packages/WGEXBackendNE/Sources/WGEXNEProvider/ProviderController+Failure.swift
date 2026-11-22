// SPDX-License-Identifier: MIT

import WGEXCore
import WGEXEngineInterface

extension ProviderController {
    private static let engineCodes: [EngineError: Int32] = [
        .invalidArgument: -1, .outOfMemory: -2, .invalidHandle: -3, .tun: -4,
        .bind: -5, .config: -6, .up: -7, .state: -8, .abiMismatch: -8, .deviceClosed: -9, .internal: -99,
    ]

    // swiftformat:disable:next redundantInternal
    internal static func failure(_ error: any Error) -> TunnelError {
        if let error = error as? TunnelError {
            return error
        }
        if let engineError = error as? EngineError {
            if case let .unknown(code) = engineError {
                return .engine(code: code)
            }
            return .engine(code: engineCodes[engineError] ?? -99)
        }
        if error is CancellationError {
            return .cancelled
        }
        return .backendUnavailable
    }
}
