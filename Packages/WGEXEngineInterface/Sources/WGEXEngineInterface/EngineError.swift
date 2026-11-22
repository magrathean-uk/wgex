// SPDX-License-Identifier: MIT

/// Engine failures mapped from the C ABI codes (`wgex_error_t`, 02 §6.2).
public enum EngineError: Error, Codable, Sendable, Hashable {
    /// The linked engine ABI version does not match the imported header.
    case abiMismatch
    /// `WGEX_EINVAL`.
    case invalidArgument
    /// `WGEX_ENOMEM`.
    case outOfMemory
    /// `WGEX_EHANDLE`.
    case invalidHandle
    /// `WGEX_ETUN`.
    case tun
    /// `WGEX_EBIND`.
    case bind
    /// `WGEX_ECONFIG`; a full apply restored its previous configuration, or an endpoint update was rejected without a rollback promise.
    case config
    /// `WGEX_EUP`.
    case up
    /// `WGEX_ESTATE`.
    case state
    /// `WGEX_EDEVICECLOSED`; destroy this engine and create a replacement.
    case deviceClosed
    /// `WGEX_EINTERNAL`.
    case `internal`
    /// A code this build does not know.
    case unknown(code: Int32)

    private static let codes: [Int32: EngineError] = [
        -1: .invalidArgument, -2: .outOfMemory, -3: .invalidHandle, -4: .tun,
        -5: .bind, -6: .config, -7: .up, -8: .state, -9: .deviceClosed, -99: .internal,
    ]

    /// Maps a C return code; nil for success (`WGEX_OK` or a positive value).
    public init?(code: Int32) {
        guard code < 0 else { return nil }
        self = Self.codes[code] ?? .unknown(code: code)
    }
}
