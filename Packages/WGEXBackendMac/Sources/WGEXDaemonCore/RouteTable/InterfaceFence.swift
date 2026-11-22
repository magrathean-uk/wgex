// SPDX-License-Identifier: MIT
import WGEXCore

/// The M1-18 ownership fences. Neither reads the kernel's ifi_lastchange: XNU moves it in whole seconds with no change by
/// the daemon (guest run 6, every connect), so a stamp comparison refused tunnels the daemon still owned.
public enum InterfaceFence: Sendable, Hashable {
    /// The daemon's utun: the same name and index, this process's descriptor for the recorded generation still open and
    /// reporting the name, and every address the daemon assigned still present. Pass no addresses before the configure
    /// assigns them, or where only interface ownership matters (route observation and teardown).
    case tunnel(addresses: [IPAddressRange])
    /// A physical interface (en0, the canary route's interface): the same name, index and link-layer address.
    case underlay

    /// The check that refused. Lab builds alone name it (`DaemonDiagnostics.breachLabels`), so Release carries no text.
    public enum Breach: Sendable, CaseIterable {
        /// No interface with the recorded name.
        case absent
        /// Another interface index under the recorded name.
        case index
        /// The descriptor is closed, reports another name, belongs to another generation, or was never recorded.
        case descriptor
        /// Another link-layer address.
        case linkAddress
        /// An address the daemon assigned is gone.
        case address
    }

    /// The first refused check, or nil when `current` (and `present`, for a tunnel with addresses) still match `recorded`.
    public func breach(recorded: TunnelIdentity, current: TunnelIdentity?, present: [IPAddressRange]) -> Breach? {
        guard let current, current.name == recorded.name else { return .absent }
        guard current.interfaceIndex == recorded.interfaceIndex else { return .index }
        switch self {
        case let .tunnel(addresses):
            guard recorded.descriptor != nil, current.descriptor == recorded.descriptor else { return .descriptor }
            let assigned = Set(present.map(\.address))
            return addresses.allSatisfy { assigned.contains($0.address) } ? nil : .address
        case .underlay:
            return current.linkAddress == recorded.linkAddress ? nil : .linkAddress
        }
    }
}

public extension InterfaceIdentityReading {
    /// Reads the interface once and applies `fence`; returns the refusing check and the observed identity, or nil.
    func breach(of recorded: TunnelIdentity, fence: InterfaceFence) async throws -> (InterfaceFence.Breach, TunnelIdentity?)? {
        let current = try await identity(named: recorded.name)
        var present: [IPAddressRange] = []
        if case let .tunnel(addresses) = fence, !addresses.isEmpty, current != nil {
            present = try await self.addresses(named: recorded.name)
        }
        return fence.breach(recorded: recorded, current: current, present: present).map { ($0, current) }
    }

    /// True when `fence` admits the recorded identity.
    func admits(_ recorded: TunnelIdentity, fence: InterfaceFence) async throws -> Bool {
        try await breach(of: recorded, fence: fence) == nil
    }
}

package extension GenerationResources {
    /// The canary route is fenced by its physical interface; every other owned route by the daemon's utun.
    func fence(for route: RouteSpec) -> InterfaceFence {
        canaryRoute?.routes.contains(route) == true ? .underlay : .tunnel(addresses: [])
    }
}
