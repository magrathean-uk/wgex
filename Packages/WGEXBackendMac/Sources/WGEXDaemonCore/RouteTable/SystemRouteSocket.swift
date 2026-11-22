// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Construction is inert. Lab builds additionally require the guarded guest before opening a descriptor.
public actor SystemRouteSocket: RouteMessageExchanging {
    private let slot = SerialOperationSlot()
    private let operations: RouteSocketOperations
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {
        operations = .system
    }

    package init(operations: RouteSocketOperations) {
        self.operations = operations
    }

    /// Reads a bounded, dual-family route dump; no route socket or mutation is used.
    public func dump() throws -> [RouteMessage]? {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP2, 0]
            for _ in 0 ..< 3 {
                var size = 0
                guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0,
                      size <= 16 * 1024 * 1024 else { throw DaemonFailure.hostSystem(errno) }
                if size == 0 {
                    return []
                }
                var data = Data(count: size)
                let status = data.withUnsafeMutableBytes { sysctl(&mib, UInt32(mib.count), $0.baseAddress, &size, nil, 0) }
                if status != 0, errno == ENOMEM {
                    continue
                }
                guard status == 0 else { throw DaemonFailure.hostSystem(errno) }
                return try RouteMessageCodec.parseDump(Data(data.prefix(size)))
            }
            throw DaemonFailure.hostSystem(ENOMEM)
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Sends one route request and waits for its matching acknowledgement.
    public func exchange(_ request: Data) async throws -> RouteMessage {
        #if os(macOS)
            try await slot.acquire(); defer { slot.release() }
            try Task.checkCancellation()
            let expected = try RouteMessageCodec.parse(request)
            guard let operation = RouteOperation(rawValue: expected.type) else { throw DaemonFailure.routeUnsupported }
            let fd = try operations.open()
            defer { operations.close(fd) }
            if let error = operations.write(fd, request) {
                // XNU reports these outcomes synchronously from write(2). Absence and an existing ADD key are
                // ownership questions for the caller's lookup, never a transport failure (M1-17 D13).
                let absent = error == ESRCH && (operation == .get || operation == .delete)
                guard absent || (error == EEXIST && operation == .add) else { throw DaemonFailure.hostSystem(error) }
                var reply = Array(request)
                RouteMessageCodec.put(UInt32(error), at: 24, into: &reply)
                return try RouteMessageCodec.parse(Data(reply))
            }
            let deadline = ContinuousClock.now.advanced(by: .seconds(2))
            while ContinuousClock.now < deadline {
                try Task.checkCancellation()
                if let bytes = try operations.read(fd), let reply = try? RouteMessageCodec.parse(bytes),
                   RouteMessageCodec.isReply(reply, operation: operation, sequence: expected.sequence, pid: expected.pid)
                {
                    return reply
                }
                try await ContinuousClock().sleep(for: .milliseconds(10))
            }
            throw DaemonFailure.portTimedOut
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }
}
