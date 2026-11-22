// SPDX-License-Identifier: MIT
import WGEXDaemonCore
import WGEXDaemonProtocol

public extension PFCtl {
    struct StockAnchorReport: Sendable {
        /// Whether fixture readback contains the stock calling anchor.
        public let present: Bool
        /// Fixture sibling-anchor listing.
        public let siblingAnchors: String
    }

    func stockAnchorReport() async throws -> StockAnchorReport {
        let main = try await command(["-s", "rules"])
        let siblings = try await command(["-a", "com.apple", "-s", "Anchors", "-v"])
        return StockAnchorReport(present: PacketFilterReadback.stockAnchorPresent(main.stdout), siblingAnchors: siblings.stdout)
    }

    func verifyStockAnchor() async throws -> String {
        let report = try await stockAnchorReport()
        guard report.present else { throw DaemonFailure.pfVerification }
        return report.siblingAnchors
    }
}
