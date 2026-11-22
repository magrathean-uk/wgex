// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

package extension DaemonDispatcher {
    /// The status reads that are answered from a measurement rather than by the service; nil for every other request.
    func statusRead(_ request: Request, context: DaemonRequestContext) async throws -> Reply? {
        switch request {
        case .protectionReasons: await protectionReasons(context: context)
        case .statusTelemetry: try await statusTelemetry(context: context)
        default: nil
        }
    }

    /// Uses the actual measurement, so saved DNS settings cannot masquerade as applied DNS.
    func protectionReasons(context: DaemonRequestContext) async -> Reply {
        let reply = await service.handle(.status, context: context, secrets: nil)
        guard case let .status(status) = reply else { return reply }
        let profileID = await service.activeProfileID()
        let qualified = await service.qualifyStatus(status, profileID: profileID)
        return .protectionReasons(qualified.reasons)
    }
}
