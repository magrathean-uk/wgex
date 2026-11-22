// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

public extension DaemonClient {
    /// The daemon's redacted diagnostics archive (`Request.diagnostics`). The bytes are the daemon's reply, unchanged.
    func diagnostics(_ options: DiagnosticsRequest) async throws -> DiagnosticsBundle {
        guard case let .diagnostics(bundle) = try await request(.diagnostics(options)) else { throw DaemonError.malformedMessage }
        return bundle
    }
}
