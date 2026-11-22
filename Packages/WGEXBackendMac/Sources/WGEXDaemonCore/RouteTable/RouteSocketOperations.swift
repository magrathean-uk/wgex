// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Descriptor operations are injected as a unit so host regressions never open a route socket.
package struct RouteSocketOperations: Sendable {
    package let open: @Sendable () throws -> Int32
    package let write: @Sendable (Int32, Data) -> Int32?
    package let read: @Sendable (Int32) throws -> Data?
    package let close: @Sendable (Int32) -> Void

    package static let system = Self(open: {
        #if WGEX_LAB_BUILD
            guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
        #endif
        let fd = socket(PF_ROUTE, SOCK_RAW, 0)
        guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
            let error = errno; Darwin.close(fd); throw DaemonFailure.hostSystem(error)
        }
        return fd
    }, write: { fd, data in
        let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        if count == data.count {
            return nil
        }
        return count < 0 ? errno : EIO
    }, read: { fd in
        var bytes = [UInt8](repeating: 0, count: 65536)
        let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        if count > 0 {
            return Data(bytes.prefix(count))
        }
        guard count >= 0 || errno == EAGAIN || errno == EINTR else { throw DaemonFailure.hostSystem(errno) }
        return nil
    }, close: { Darwin.close($0) })
}
