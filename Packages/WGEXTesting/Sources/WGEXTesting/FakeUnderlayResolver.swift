// SPDX-License-Identifier: MIT

import Synchronization
import WGEXCore

/// ``UnderlayResolving`` stand-in with canned answers; fault point `resolve`.
public final class FakeUnderlayResolver: UnderlayResolving {
    /// A recorded query.
    public struct Query: Sendable, Hashable {
        /// Queried host.
        public let host: String
        /// Interface index the query was bound to.
        public let interfaceIndex: UInt32
    }

    /// Faults consumed by `resolve`.
    public let faults: FaultInjector
    private let answers: Mutex<[String: [String]]>
    private let queries = Mutex<[Query]>([])

    /// Creates a resolver with canned answers per host.
    public init(answers: [String: [String]] = [:], faults: FaultInjector = FaultInjector()) {
        self.answers = Mutex(answers)
        self.faults = faults
    }

    /// Queries received so far.
    public var receivedQueries: [Query] {
        queries.withLock { $0 }
    }

    /// Replaces the answer for `host`.
    public func setAnswer(_ addresses: [String], for host: String) {
        answers.withLock { $0[host] = addresses }
    }

    /// The canned answer, or `.noAnswer`.
    public func resolve(host: String, interfaceIndex: UInt32) async throws(DaemonPortError) -> [String] {
        queries.withLock { $0.append(Query(host: host, interfaceIndex: interfaceIndex)) }
        if let error = faults.fault(at: "resolve", as: DaemonPortError.self) {
            throw error
        }
        guard let addresses = answers.withLock({ $0[host] }), !addresses.isEmpty else { throw .noAnswer }
        return addresses
    }
}
