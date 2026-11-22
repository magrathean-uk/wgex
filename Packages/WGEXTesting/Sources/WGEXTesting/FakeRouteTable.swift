// SPDX-License-Identifier: MIT

import Synchronization
import WGEXCore

/// ``RouteProgramming`` stand-in; fault points `install` and `remove`.
public final class FakeRouteTable: RouteProgramming {
    /// Faults consumed by the operations.
    public let faults: FaultInjector
    private let routes = Mutex<[Generation: [RouteSpec]]>([:])

    /// Creates an empty table.
    public init(faults: FaultInjector = FaultInjector()) {
        self.faults = faults
    }

    /// Routes per generation.
    public var routesByGeneration: [Generation: [RouteSpec]] {
        routes.withLock { $0 }
    }

    /// Records the routes.
    public func install(_ newRoutes: [RouteSpec], generation: Generation) async throws(DaemonPortError) {
        if let error = faults.fault(at: "install", as: DaemonPortError.self) {
            throw error
        }
        routes.withLock { $0[generation, default: []] += newRoutes }
    }

    /// Drops the generation's routes; `.notOwned` when it has none.
    public func removeRoutes(of generation: Generation) async throws(DaemonPortError) {
        if let error = faults.fault(at: "remove", as: DaemonPortError.self) {
            throw error
        }
        let removed = routes.withLock { $0.removeValue(forKey: generation) }
        if removed == nil {
            throw .notOwned
        }
    }

    /// Every recorded route.
    public func ownedRoutes() async -> [RouteSpec] {
        routes.withLock { $0.sorted { $0.key < $1.key }.flatMap(\.value) }
    }
}
