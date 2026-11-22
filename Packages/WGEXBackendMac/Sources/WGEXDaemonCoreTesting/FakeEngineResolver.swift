// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonCore
import WGEXPolicy

/// Records fixture queries and returns a supplied DNS response without network I/O.
public actor FakeEngineResolver: EngineResolveCalling {
    /// One fixture resolver query, containing no secret material.
    public struct Query: Sendable, Equatable {
        /// Requested fixture hostname.
        public let host: String
        /// Supplied physical IPv4 interface index.
        public let v4: UInt32?
        /// Supplied physical IPv6 interface index.
        public let v6: UInt32?
        /// Supplied primary-service resolver addresses.
        public let resolvers: [String]
    }

    /// Ordered resolver queries received by this fixture.
    public private(set) var queries: [Query] = []
    private let response: Data
    /// Creates the inert fixture with explicitly supplied state.
    public init(response: Data) {
        self.response = response
    }

    /// Records the supplied query and returns the injected response.
    public func resolve(host: String, v4: UInt32?, v6: UInt32?, resolvers: [String]) -> Data {
        queries.append(Query(host: host, v4: v4, v6: v6, resolvers: resolvers)); return response
    }
}
