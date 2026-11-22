// SPDX-License-Identifier: MIT
import Darwin
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol

/// Legacy codec probes retain their own explicit dependencies; no production actor state is exposed.
public actor LegacyRouteProbe {
    private let table: RouteTable
    private let journal: any DaemonJournalling
    private let kernel: any RouteMessageExchanging
    private let identities: any InterfaceIdentityReading
    private let pid: Int32
    private var sequence = RouteSequence()

    /// Supplies only public production ports and the same fixture journal used by the table.
    public init(
        table: RouteTable,
        journal: any DaemonJournalling,
        kernel: any RouteMessageExchanging,
        identities: any InterfaceIdentityReading,
        pid: Int32,
    ) {
        self.table = table; self.journal = journal; self.kernel = kernel; self.identities = identities; self.pid = pid
    }

    /// Observes a fixture route through the public ownership inspector.
    public func get(_ route: RouteSpec, generation: Generation) async throws -> ObservedDaemonRoute? {
        let expected = try resource(generation)
        guard expected.routes.contains(route) else { throw DaemonFailure.portNotOwned }
        return try await table.observed(expected).first(where: { $0.route == route })
    }

    /// Exercises the retired RTM_CHANGE codec contract against an explicitly injected kernel.
    public func change(_ route: RouteSpec, generation: Generation) async throws {
        let expected = try resource(generation)
        guard let identity = expected.identity, expected.routes.contains(route) else { throw DaemonFailure.portNotOwned }
        try await check(identity)
        let current = try await send(.get, route: route, identity: identity)
        guard current.error == 0, current.hasOwnershipMark, current.matches(route, index: identity.interfaceIndex) else {
            throw DaemonFailure.portNotOwned
        }
        try await check(identity)
        try Task.checkCancellation()
        let result = try await send(.change, route: route, identity: identity)
        guard result.error == 0 else { throw DaemonFailure.portSystem(code: result.error) }
    }

    private func resource(_ generation: Generation) throws -> GenerationResources {
        guard let resource = journal.snapshot().resources.first(where: { $0.generation == generation }),
              resource.routeFlags & GenerationResources.protocol2RouteFlag != 0 else { throw DaemonFailure.portNotOwned }
        return resource
    }

    private func check(_ identity: TunnelIdentity) async throws {
        guard try await identities.identity(named: identity.name) == identity else { throw DaemonFailure.portNotOwned }
    }

    private func send(_ operation: RouteOperation, route: RouteSpec, identity: TunnelIdentity) async throws -> RouteMessage {
        let stamp = try sequence.next()
        let data = try RouteMessageCodec.build(operation, route: route, index: identity.interfaceIndex, sequence: stamp, pid: pid)
        let reply = try await kernel.exchange(data)
        guard RouteMessageCodec.isReply(reply, operation: operation, sequence: stamp, pid: pid) else {
            throw DaemonFailure.routeMalformed
        }
        return reply
    }
}
