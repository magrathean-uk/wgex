// SPDX-License-Identifier: MIT
import Darwin
import Dispatch
import Foundation
import WGEXDaemonProtocol

/// Readiness-driven PF_ROUTE observation; construction never opens a socket.
public actor SystemRouteMonitor: RouteMonitoring {
    private var source: any DispatchSourceRead?
    /// Creates an inert route monitor.
    public init() {}
    /// Opens a nonblocking socket with room for route bursts.
    public func start() throws -> AsyncStream<RouteNotification> {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard source == nil else { throw DaemonFailure.hostAlreadyStarted }
            let fd = socket(PF_ROUTE, SOCK_RAW, 0)
            guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
            var capacity: Int32 = 4 * 1024 * 1024
            guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &capacity, socklen_t(MemoryLayout.size(ofValue: capacity))) == 0
            else { close(fd); throw DaemonFailure.hostSystem(errno) }
            let pair = AsyncStream<RouteNotification>.makeStream()
            source = Self.makeSource(fd: fd, sink: pair.continuation)
            pair.continuation.onTermination = { [weak self] _ in Task { await self?.stop() } }
            return pair.stream
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Cancels the source; its cancellation handler owns descriptor closure.
    public func stop() {
        source?.cancel(); source = nil
    }

    isolated deinit { source?.cancel() }

    private static func makeSource(fd: Int32, sink: AsyncStream<RouteNotification>.Continuation) -> any DispatchSourceRead {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "WGEX.routes"))
        source.setEventHandler {
            var bytes = [UInt8](repeating: 0, count: 65536)
            do {
                try drainRouteNotifications(read: {
                    while true {
                        let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                        if count > 0 {
                            return Data(bytes.prefix(count))
                        }
                        if count < 0, errno == EINTR {
                            continue
                        }
                        if count < 0, errno == EAGAIN {
                            return nil
                        }
                        throw DaemonFailure.hostSystem(errno)
                    }
                }, emit: { event in
                    if !Self.ignored(event.index) {
                        sink.yield(event)
                    }
                })
            } catch { sink.finish() }
        }
        source.setCancelHandler { close(fd); sink.finish() }
        source.resume()
        return source
    }

    private static func ignored(_ index: UInt16) -> Bool {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(UInt32(index), &name) != nil else { return false }
        let value = String(decoding: name.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return value.hasPrefix("awdl") || value.hasPrefix("llw")
    }
}
