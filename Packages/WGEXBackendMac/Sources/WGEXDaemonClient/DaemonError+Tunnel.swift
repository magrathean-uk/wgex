// SPDX-License-Identifier: MIT
import WGEXCore
import WGEXDaemonProtocol

public extension DaemonError {
    /// The shell-facing category of a daemon error; payload text never crosses.
    var tunnelError: TunnelError {
        presentation.tunnelError
    }

    /// Fixed client copy; never displays arbitrary error payloads from a privileged process.
    var userMessage: String {
        switch self {
        case .busy: "An operation is already in progress"
        case .recovering: "Service is recovering; check the current protection state"
        case .secretsUnavailable: "Open WGEX to reconnect"
        default: "Service could not complete the request"
        }
    }

    /// Runs `action` and rethrows any `DaemonError` as its ``tunnelError``.
    static func mapping<Value>(_ action: () async throws -> Value) async throws -> Value {
        do { return try await action() }
        catch let error as DaemonError { throw error.tunnelError }
    }
}
