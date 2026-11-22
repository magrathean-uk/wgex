// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

public extension TunnelController {
    /// A profile without DNS may carry tunnel traffic but cannot support a tunnel-DNS protection claim.
    /// Applying this at the XPC boundary covers status replies and every pushed heartbeat without
    /// changing the controller's blocking policy or the unrelated lifecycle implementation.
    func qualifyStatus(_ status: TunnelStatus, profileID: UUID?) async -> QualifiedDaemonStatus {
        let epoch = generation
        let id = profileID ?? intended?.profileID
        guard let id else {
            if status.protection == .protected {
                var unknown = status; unknown.protection = .unknown; unknown.protectionNote = .dnsUnverified
                return QualifiedDaemonStatus(status: unknown, reasons: [.dnsUnverified])
            }
            return QualifiedDaemonStatus(status: status, reasons: [])
        }
        let configuredDNS = await registry.cachedDNSConfigured(id)
        let appliedDNS = journal.snapshot().resources.contains {
            $0.generation == epoch && $0.dnsKey != nil && $0.dns?.servers.isEmpty == false
        }
        let requiresAppliedDNS = status.protection == .protected
        guard generation == epoch, configuredDNS == true,
              !requiresAppliedDNS || (intended?.profileID == id && appliedDNS)
        else {
            var qualified = status
            if qualified.protectionNote == nil {
                qualified.protectionNote = .dnsUnverified
            }
            if qualified.protection == .protected {
                qualified.protection = .unknown
            }
            return QualifiedDaemonStatus(status: qualified, reasons: [.dnsUnverified])
        }
        return QualifiedDaemonStatus(status: status, reasons: [])
    }
}
