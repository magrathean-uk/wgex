// SPDX-License-Identifier: MIT
import Foundation

public struct TransportPolicy: Codable, Sendable, Hashable {
    public var candidates: [TransportCandidate] // ordered; `.udp` first by default
    public var selection: TransportSelection // .manual(TransportID) | .automatic(FailoverPolicy)

    public init(candidates: [TransportCandidate], selection: TransportSelection) {
        self.candidates = candidates; self.selection = selection
    }

    /// One UDP candidate, automatic failover armed, no automatic failback.
    public static func udp(id: TransportID = TransportID()) -> TransportPolicy {
        TransportPolicy(candidates: [TransportCandidate(id: id, name: "UDP", spec: .udp)], selection: .automatic(.defaults(order: [id])))
    }
}

public struct TransportCandidate: Codable, Sendable, Hashable, Identifiable {
    public var id: TransportID
    public var name: String
    public var spec: TransportSpec

    public init(id: TransportID = TransportID(), name: String, spec: TransportSpec) {
        self.id = id; self.name = name; self.spec = spec
    }
}

public enum TransportSelection: Codable, Sendable, Hashable {
    case manual(TransportID)
    case automatic(FailoverPolicy)
}

public struct FailoverPolicy: Codable, Sendable, Hashable {
    public var unhealthyWindows: Int // 2 × 15 s windows of tx-without-rx
    public var recoveryWindow: Duration // 30 s without failures → healthy
    public var failedEpisodeBackoff: Duration // 600 s: suppresses automatic switching; the current candidate keeps retrying with its own
    // backoff
    public var order: [TransportID]
    public var automaticFailback: Bool // false

    public init(
        unhealthyWindows: Int, recoveryWindow: Duration, failedEpisodeBackoff: Duration,
        order: [TransportID], automaticFailback: Bool,
    ) {
        self.unhealthyWindows = unhealthyWindows; self.recoveryWindow = recoveryWindow
        self.failedEpisodeBackoff = failedEpisodeBackoff; self.order = order; self.automaticFailback = automaticFailback
    }

    public static func defaults(order: [TransportID] = []) -> FailoverPolicy {
        FailoverPolicy(
            unhealthyWindows: 2,
            recoveryWindow: .seconds(30),
            failedEpisodeBackoff: .seconds(600),
            order: order,
            automaticFailback: false,
        )
    }
}
