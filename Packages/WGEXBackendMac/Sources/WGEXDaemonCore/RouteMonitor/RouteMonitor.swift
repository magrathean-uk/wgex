// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

public struct RouteNotification: Sendable, Equatable {
    public let type: UInt8
    public let index: UInt16
    public let pid: Int32?
    /// Kernel route flags; interface messages carry no route flags.
    public let flags: UInt32
    public init(type: UInt8, index: UInt16, pid: Int32?, flags: UInt32 = 1) {
        self.type = type; self.index = index; self.pid = pid; self.flags = flags
    }

    public static func parse(_ data: Data) throws -> RouteNotification {
        let bytes = Array(data)
        guard bytes.count >= 4, RouteMessageCodec.integer(bytes, 0, 2) == bytes.count, bytes[2] == 5 else {
            throw DaemonFailure.routeMalformed
        }
        switch bytes[3] {
        case 1, 2, 3:
            let message = try RouteMessageCodec.parse(data)
            return RouteNotification(type: message.type, index: message.index, pid: message.pid, flags: message.flags)
        case 12, 13, 14:
            // ifa_msghdr and if_msghdr use index at 12; they have no pid field.
            guard bytes.count >= (bytes[3] == 14 ? 112 : 20) else { throw DaemonFailure.routeMalformed }
            return RouteNotification(type: bytes[3], index: UInt16(RouteMessageCodec.integer(bytes, 12, 2)), pid: nil)
        default: throw DaemonFailure.routeUnsupported
        }
    }
}

public protocol RouteMonitoring: Sendable {
    func start() async throws -> AsyncStream<RouteNotification>
    func stop() async
}

/// Trailing debounce with a two-second ceiling even when notifications never stop.
public struct RouteMonitorModel: Sendable {
    public private(set) var deadline: Duration?
    private let ownPID: Int32
    private var firstEvent: Duration?
    /// The deadline that a continuous route burst cannot move.
    public var maximumDeadline: Duration? {
        firstEvent.map { $0 + .seconds(2) }
    }

    /// Interfaces owned by the daemon or irrelevant to physical underlay changes.
    public var ignoredIndices: Set<UInt16> = []
    public init(ownPID: Int32) {
        self.ownPID = ownPID
    }

    @discardableResult
    public mutating func receive(_ notification: RouteNotification, at now: Duration) -> Bool {
        guard notification.pid != ownPID, [1, 2, 3, 12, 13, 14].contains(notification.type), !ignoredIndices.contains(notification.index),
              notification.flags & 0x20400 == 0 else { return false }
        if firstEvent == nil {
            firstEvent = now
        }
        deadline = min(now + .milliseconds(300), (firstEvent ?? now) + .seconds(2)); return true
    }

    public mutating func takeReconciliation(at now: Duration) -> Bool {
        guard let deadline, now >= deadline else { return false }
        self.deadline = nil; firstEvent = nil; return true
    }
}

/// Drains every queued datagram before yielding readiness ownership back to Dispatch.
package func drainRouteNotifications(
    read: () throws -> Data?, emit: (RouteNotification) -> Void,
) rethrows {
    while let bytes = try read() {
        if let event = try? RouteNotification.parse(bytes) {
            emit(event)
        }
    }
}
