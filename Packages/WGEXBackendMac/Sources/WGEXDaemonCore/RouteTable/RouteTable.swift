// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Reads interface identities for the ownership fences (InterfaceFence). Never derived from a name alone, a random value
/// or the kernel's ifi_lastchange (M1-18).
public protocol InterfaceIdentityReading: Sendable {
    /// Name and index, the link-layer address when the interface has one, and for a utun this process's open descriptor
    /// that reports the name (TunnelDescriptor); nil when no interface has the name.
    func identity(named name: String) async throws -> TunnelIdentity?
    /// Addresses currently assigned to the interface; only the host address is compared.
    func addresses(named name: String) async throws -> [IPAddressRange]
}

/// Route requests and optional bulk observation share one kernel port.
public protocol RouteMessageExchanging: Sendable {
    func exchange(_ request: Data) async throws -> RouteMessage
    /// Returns nil when the kernel port requires individual route lookups.
    func dump() async throws -> [RouteMessage]?
}

public extension RouteMessageExchanging {
    /// Ports without a dump implementation retain ownership-checked RTM_GET verification.
    func dump() async throws -> [RouteMessage]? {
        nil
    }
}

/// Secondary seam: Core's RouteProgramming cannot report verification errors or accept a journal identity.
public protocol DaemonRouteProgramming: Sendable {
    /// Resolves the current physical interface identity before write-ahead ownership is recorded.
    func canaryRoute(underlay: UnderlaySnapshot) async throws -> OwnedCanaryRoute?
    /// Installs only routes owned by this generation.
    func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonFailure)
    /// Removes only this generation's owned routes.
    func removeRoutes(of generation: Generation) async throws(DaemonFailure)
    /// Removes only the journalled underlay canary route, preserving tunnel routes.
    func removeCanaryRoute(of generation: Generation) async throws(DaemonFailure)
    /// Removes only the listed journalled routes of the generation (an exclusion re-carve, DEC-087), keeping the rest.
    func removeRoutes(_ routes: [RouteSpec], of generation: Generation) async throws(DaemonFailure)
    /// Reports currently observed owned routes.
    func ownedRoutes() async -> [RouteSpec]
}

public extension DaemonRouteProgramming {
    func removeCanaryRoute(of _: Generation) async throws(DaemonFailure) {
        throw .portNotOwned
    }

    func removeRoutes(_: [RouteSpec], of _: Generation) async throws(DaemonFailure) {
        throw .portNotOwned
    }

    func canaryRoute(underlay: UnderlaySnapshot) async throws -> OwnedCanaryRoute? {
        guard underlay.ipv4Router == nil else { throw DaemonFailure.portNotOwned }
        return nil
    }
}

/// Route programming and ownership inspection belong to one daemon port.
public protocol OwnedRouteInspecting: DaemonRouteProgramming {
    func observed(_ resources: GenerationResources) async throws -> [ObservedDaemonRoute]
    func reconcile(_ resources: GenerationResources) async throws
}

public actor RouteTable: OwnedRouteInspecting {
    /// Darwin net/route.h RTF_WASCLONED.
    private static let clonedFlag: UInt32 = 0x20000
    /// Darwin net/route.h RTF_IFSCOPE.
    private static let scopedFlag: UInt32 = 0x1000000
    private let journal: any DaemonJournalling
    private let kernel: any RouteMessageExchanging
    private let identities: any InterfaceIdentityReading
    private let pid: Int32
    private var sequences = RouteSequence()
    /// Generations whose canary this table added itself; any other owned canary it meets is an adoption (Lab log only).
    private var addedCanaries: Set<Generation> = []
    private let slot = SerialOperationSlot()

    public init(journal: any DaemonJournalling, kernel: any RouteMessageExchanging, identities: any InterfaceIdentityReading, pid: Int32) {
        self.journal = journal; self.kernel = kernel; self.identities = identities; self.pid = pid
    }

    public func canaryRoute(underlay: UnderlaySnapshot) async throws -> OwnedCanaryRoute? {
        guard let index = underlay.v4 else { return nil }
        guard let name = underlay.interfaceV4Name, let router = underlay.ipv4Router,
              let identity = try await identities.identity(named: name), identity.interfaceIndex == index
        else { throw Self.refused(.canaryInterfaceMissing) }
        return try OwnedCanaryRoute(identity: identity, router: router)
    }

    public func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonFailure) {
        try await slot.acquirePort(); defer { slot.release() }
        do {
            try Task.checkCancellation()
            let resource = try resource(generation)
            guard routes.allSatisfy(resource.routes.contains), resource.identity != nil else { throw DaemonFailure.portNotOwned }
            for route in routes {
                do { try await installRoute(route, resource: resource) }
                catch { throw Self.reported(error, route: route, canary: resource.canaryRoute) }
            }
        } catch let error as DaemonFailure where error.isPortFailure { throw error }
        catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(error, context: "route table")
            #endif
            throw .portSystem(code: EIO)
        }
    }

    /// Adopts an owned route, replaces our own leaked canary, refuses anything foreign; adds only what is absent.
    private func installRoute(_ route: RouteSpec, resource: GenerationResources) async throws {
        guard let identity = identity(for: route, resource: resource) else { throw DaemonFailure.portNotOwned }
        let fence = resource.fence(for: route)
        try await checkIdentity(identity, fence: fence)
        if let existing = try await lookup(route, identity: identity, canary: resource.canaryRoute) {
            if owns(existing, route: route, resource: resource) {
                noteCanary(route, resource: resource, added: false)
                return
            }
            guard leakedCanary(existing, route: route, resource: resource) else { throw Self.refused(.foreignRoute) }
            try await replaceLeakedCanary(existing, route: route, identity: identity, resource: resource)
        }
        try await checkIdentity(identity, fence: fence)
        try Task.checkCancellation()
        let reply = try await send(.add, route: route, identity: identity, canary: resource.canaryRoute)
        if reply.error == EEXIST {
            guard let current = try await lookup(route, identity: identity, canary: resource.canaryRoute), owns(
                current,
                route: route,
                resource: resource,
            ) else {
                throw Self.refused(.foreignRoute)
            }
            noteCanary(route, resource: resource, added: false)
        } else if reply.error != 0 {
            throw DaemonFailure.portSystem(code: reply.error)
        } else {
            noteCanary(route, resource: resource, added: true)
        }
    }

    public func removeRoutes(of generation: Generation) async throws(DaemonFailure) {
        // Rollback runs in a cancelled predecessor. Drain an independent, owned transaction;
        // identity checks and each system exchange's deadline remain in force.
        let cleanup = Task { try await self.removeTransaction(of: generation, canaryOnly: false) }
        do { try await cleanup.value }
        catch let failure as DaemonFailure { throw failure }
        catch { throw .portSystem(code: EIO) }
    }

    private func removeTransaction(
        of generation: Generation, canaryOnly: Bool, only: Set<RouteSpec>? = nil,
    ) async throws(DaemonFailure) {
        try await slot.acquirePort(); defer { slot.release() }
        do {
            guard let resource = journal.snapshot().resources.first(where: { $0.generation == generation }) else { return }
            let underlay = resource.canaryRoute?.routes ?? []
            for route in Self.removalOrder(resource) where (!canaryOnly || underlay.contains(route)) &&
                only.map({ $0.contains(route) && !underlay.contains(route) }) ?? true
            {
                let canary = underlay.contains(route)
                guard let identity = identity(for: route, resource: resource),
                      try await removable(identity, canary: canary),
                      let current = try await lookup(route, identity: identity, canary: resource.canaryRoute),
                      owns(current, route: route, resource: resource),
                      try await removable(identity, canary: canary) else { continue }
                let reply = try await send(.delete, route: route, identity: identity, canary: resource.canaryRoute)
                guard reply.error == 0 || reply.error == ESRCH else { throw DaemonFailure.portSystem(code: reply.error) }
            }
        } catch let error as DaemonFailure where error.isPortFailure { throw error }
        catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(error, context: "route table")
            #endif
            throw .portSystem(code: EIO)
        }
    }

    public func ownedRoutes() async -> [RouteSpec] {
        var result: [RouteSpec] = []
        for resource in journal.snapshot().resources {
            await result += (try? observed(resource).map(\.route)) ?? []
        }
        return result
    }

    public func observed(_ resources: GenerationResources) async throws -> [ObservedDaemonRoute] {
        try await slot.acquire(); defer { slot.release() }
        guard resources.routeFlags & GenerationResources.protocol2RouteFlag != 0 else { return [] }
        var result: [ObservedDaemonRoute] = []
        var current: Set<TunnelIdentity> = []
        // Tunnel routes are observed while the utun is held (name, index, descriptor); the canary while en0 keeps its
        // name, index and link-layer address. No stamp is compared (M1-18).
        if let identity = resources.identity, try await identities.admits(identity, fence: .tunnel(addresses: [])) {
            current.insert(identity)
        }
        if let identity = resources.canaryRoute?.identity, try await identities.admits(identity, fence: .underlay) {
            current.insert(identity)
        }
        let dump = try await kernel.dump()
        var index: [RouteLookupKey: RouteMessage] = [:]
        for message in dump ?? [] {
            guard let key = RouteLookupKey(message: message) else { continue }
            if index[key]?.hasOwnershipMark != false {
                index[key] = message
            }
        }
        for route in resources.routes {
            guard let identity = identity(for: route, resource: resources), current.contains(identity) else { continue }
            let message: RouteMessage? = if dump != nil, let key = RouteLookupKey(route: route, index: identity.interfaceIndex) {
                index[key]
            } else {
                try await lookup(route, identity: identity, canary: resources.canaryRoute)
            }
            if let message, message.hasOwnershipMark, dump != nil || message.matches(route, index: identity.interfaceIndex),
               matchesCanary(message, route: route, canary: resources.canaryRoute)
            {
                result.append(ObservedDaemonRoute(
                    route: route,
                    identity: identity,
                    generation: resources.generation,
                    hasProtocol2Flag: true,
                ))
            }
        }
        return result
    }

    public func reconcile(_ resources: GenerationResources) async throws {
        // install verifies all existing routes and adds only missing ones. Foreign replacements cause a blocking failure.
        try await install(resources.routes, generation: resources.generation)
    }

    private func resource(_ generation: Generation) throws -> GenerationResources {
        guard let resource = journal.snapshot().resources.first(where: { $0.generation == generation }),
              resource.routeFlags & GenerationResources.protocol2RouteFlag != 0 else { throw DaemonFailure.portNotOwned }
        return resource
    }

    private func owns(_ message: RouteMessage, route: RouteSpec, resource: GenerationResources) -> Bool {
        guard let identity = identity(for: route, resource: resource) else { return false }
        return resource.routeFlags & GenerationResources.protocol2RouteFlag != 0 && resource.routes.contains(route)
            && route.interfaceName == identity.name && message.hasOwnershipMark && message.matches(route, index: identity.interfaceIndex)
            && matchesCanary(message, route: route, canary: resource.canaryRoute)
    }

    private func identity(for route: RouteSpec, resource: GenerationResources) -> TunnelIdentity? {
        if let canary = resource.canaryRoute, canary.routes.contains(route) {
            return canary.identity
        }
        return resource.identity.flatMap { $0.name == route.interfaceName ? $0 : nil }
    }

    private func matchesCanary(_ message: RouteMessage, route: RouteSpec, canary: OwnedCanaryRoute?) -> Bool {
        guard let canary, canary.routes.contains(route) else { return true }
        return message.flags & 0x1000000 != 0 && message.flags & 2 != 0
            && message.addresses[1].flatMap(RouteMessageCodec.address)?.address == canary.router
    }

    /// A route shaped like our canary (PROTO2 mark, IFSCOPE, GATEWAY, HOST, IPv4 router, not a clone) on the canary's own
    /// scope is ours whatever its router: a leak from an earlier generation or crash. The scoped /1 halves have the same
    /// shape without HOST. Unmarked routes and marked routes of another shape remain foreign (M1-17 N7).
    private func leakedCanary(_ message: RouteMessage, route: RouteSpec, resource: GenerationResources) -> Bool {
        guard let canary = resource.canaryRoute, canary.routes.contains(route) else { return false }
        let shape: UInt32 = 0x1000000 | 0x4000 | (route == canary.route ? 4 : 0) | 2
        return message.flags & shape == shape && message.flags & Self.clonedFlag == 0
            && message.matches(route, index: canary.identity.interfaceIndex)
            && message.addresses[1].flatMap(RouteMessageCodec.address)?.isIPv6 == false
    }

    /// Deletes the leaked canary once, by its own gateway, before the caller adds the journalled one.
    private func replaceLeakedCanary(
        _ message: RouteMessage, route: RouteSpec, identity: TunnelIdentity, resource: GenerationResources,
    ) async throws {
        try await checkIdentity(identity, fence: .underlay)
        let gateway = message.addresses[1].flatMap(RouteMessageCodec.address)?.address
        let reply = try await send(.delete, route: route, identity: identity, canary: resource.canaryRoute, gateway: gateway)
        guard reply.error == 0 || reply.error == ESRCH else { throw DaemonFailure.portSystem(code: reply.error) }
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(.canaryReplaced)
        #endif
    }

    private func noteCanary(_ route: RouteSpec, resource: GenerationResources, added: Bool) {
        guard route == resource.canaryRoute?.route, addedCanaries.insert(resource.generation).inserted, !added else { return }
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(.canaryAdopted)
        #endif
    }

    private func checkIdentity(_ identity: TunnelIdentity, fence: InterfaceFence) async throws {
        if case let (breach, current)? = try await identities.breach(of: identity, fence: fence) {
            throw Self.refused(.routeInterfaceDrift, identity, current, breach)
        }
    }

    /// Lab builds name the refusing check and the failed fence check (M1-18); the failure itself is unchanged.
    private static func refused(
        _ event: DaemonDiagnostics.OwnershipEvent, _ expected: TunnelIdentity? = nil, _ current: TunnelIdentity? = nil,
        _ breach: InterfaceFence.Breach? = nil,
    ) -> DaemonFailure {
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(event)
            if let expected, let breach {
                DaemonDiagnostics.interface(expected, current: current, breach: breach)
            }
        #endif
        return .portNotOwned
    }

    /// Tunnel routes are removed only while this process still holds the utun (name, index, descriptor). The physical
    /// interface is not ours, so canary teardown is fenced by name and index plus the route's own mark, scope and
    /// journalled router (M1-17 D13); deleting that TEST-NET-1 host route never widens the policy.
    private func removable(_ identity: TunnelIdentity, canary: Bool) async throws -> Bool {
        if canary {
            guard let current = try await identities.identity(named: identity.name) else { return false }
            return current.interfaceIndex == identity.interfaceIndex
        }
        return try await identities.admits(identity, fence: .tunnel(addresses: []))
    }

    private func send(
        _ operation: RouteOperation,
        route: RouteSpec,
        identity: TunnelIdentity,
        canary: OwnedCanaryRoute?,
        gateway: String? = nil,
    ) async throws -> RouteMessage {
        guard route.interfaceName == identity.name else { throw DaemonFailure.portNotOwned }
        let sequence = try sequences.next()
        let request = try RouteMessageCodec.build(
            operation,
            route: route,
            index: identity.interfaceIndex,
            sequence: sequence,
            pid: pid,
            gateway: gateway ?? (canary?.routes.contains(route) == true ? canary?.router : nil),
        )
        let reply = try await kernel.exchange(request)
        guard RouteMessageCodec.isReply(reply, operation: operation, sequence: sequence, pid: pid)
        else { throw DaemonFailure.routeMalformed }
        return reply
    }
}

public extension RouteTable {
    func removeRoutes(_ routes: [RouteSpec], of generation: Generation) async throws(DaemonFailure) {
        guard !routes.isEmpty else { return }
        let cleanup = Task { try await self.removeTransaction(of: generation, canaryOnly: false, only: Set(routes)) }
        do { try await cleanup.value }
        catch let failure as DaemonFailure { throw failure }
        catch { throw .portSystem(code: EIO) }
    }

    func removeCanaryRoute(of generation: Generation) async throws(DaemonFailure) {
        let cleanup = Task { try await self.removeTransaction(of: generation, canaryOnly: true) }
        do { try await cleanup.value }
        catch let failure as DaemonFailure { throw failure }
        catch { throw .portSystem(code: EIO) }
    }
}

private extension RouteTable {
    func lookup(_ route: RouteSpec, identity: TunnelIdentity, canary: OwnedCanaryRoute?) async throws -> RouteMessage? {
        let reply = try await send(.get, route: route, identity: identity, canary: canary)
        if reply.error == ESRCH {
            return nil
        }
        guard reply.error == 0 else { throw DaemonFailure.portSystem(code: reply.error) }
        // RTM_GET can return a less specific route, or a kernel clone (RTF_WASCLONED, for example after a canary
        // probe) that RTM_ADD replaces. Neither satisfies this exact entry nor proves a foreign owner.
        guard reply.flags & Self.clonedFlag == 0, reply.matches(route, index: UInt32(reply.index)) else { return nil }
        // XNU answers an unscoped RTM_GET from the primary interface's scoped entries first, so while the scoped /1
        // halves (DEC-126) sit on en0 the GET for the tunnel's own unscoped /1 returns the en0 half (M08-T22, lab route
        // monitor). A scoped reply is never the unscoped entry asked for: read that entry from the route dump.
        if reply.flags & Self.scopedFlag != 0, canary?.routes.contains(route) != true {
            return try await unscopedEntry(route)
        }
        return reply
    }

    /// The unscoped, uncloned entry with the route's key on any interface (the RTM_GET answer without the primary scope);
    /// nil when the kernel port has no dump, which leaves an existing key to RTM_ADD's EEXIST check.
    func unscopedEntry(_ route: RouteSpec) async throws -> RouteMessage? {
        try await kernel.dump()?.first {
            $0.flags & (Self.scopedFlag | Self.clonedFlag) == 0 && $0.matches(route, index: UInt32($0.index))
        }
    }

    /// Tunnel routes in journal order, then the scoped halves, then the canary: the canary is installed first and removed
    /// last, so a failed tunnel-route delete never leaves the /1 routes without it and the evaluation canary keeps a route
    /// (M1-19 F1).
    static func removalOrder(_ resource: GenerationResources) -> [RouteSpec] {
        let underlay = resource.canaryRoute?.routes ?? []
        return resource.routes.filter { !underlay.contains($0) } + underlay.reversed().filter(resource.routes.contains)
    }

    /// Returns `error` unchanged. Lab builds first name the route kind whose install the kernel refused and its errno
    /// (M1-19 item 4); ownership refusals carry no errno and already have their own fixed line.
    static func reported(_ error: any Error, route: RouteSpec, canary: OwnedCanaryRoute?) -> any Error {
        #if WGEX_LAB_BUILD
            if let code = (error as? DaemonFailure)?.systemStatus {
                let kind: DaemonDiagnostics.RouteKind = if canary?.routes.contains(route) == true {
                    .canary
                } else {
                    route.destination.contains(":") ? .tunnelIPv6 : .tunnelIPv4
                }
                DaemonDiagnostics.routeFailed(kind, code: code)
            }
        #endif
        return error
    }
}
